"""Запрет сетевого доступа программам через Брандмауэр Защитника Windows.

Для каждой запрещённой программы создаются правила «Блокировать» (исходящие
и, по желанию, входящие) в группе NetActivityMonitor. Это обычные правила
Windows: они действуют, даже когда монитор закрыт, переживают перезагрузку
и видны в оснастке wf.msc («Монитор брандмауэра Защитника Windows»).

Правила создаются командлетами PowerShell (модуль NetSecurity): данные туда
и обратно передаются в base64, поэтому кириллица и любые символы в путях
не ломают команды, а ответ не зависит от языка Windows.
"""

import base64
import hashlib
import json
import logging
import ntpath
import os
import re
import subprocess
import sys
import threading
import time
from collections import namedtuple
from concurrent.futures import ThreadPoolExecutor

log = logging.getLogger('netmon.firewall')

GROUP = 'NetActivityMonitor'
DIRECTIONS = {'out': 'Outbound', 'in': 'Inbound'}
_FROM_PS_DIRECTION = {'Outbound': 'out', 'Inbound': 'in'}
CREATE_NO_WINDOW = 0x08000000

Rule = namedtuple('Rule', 'id name direction enabled program service')
# Строка списка запрещённых программ: все правила для одной пары «программа + служба»
Entry = namedtuple('Entry', 'key program service directions enabled rule_ids')

# Службы, без которых пропадёт сеть или интернет
CRITICAL_SERVICES = {
    'dnscache': 'DNS-клиент: без него перестанут открываться сайты',
    'dhcp': 'DHCP-клиент: компьютер может потерять IP-адрес',
    'nlasvc': 'определение сетей (NLA)',
    'nsi': 'служба интерфейса сетевого хранилища',
    'netprofm': 'служба списка сетей',
    'wcmsvc': 'диспетчер подключений Windows',
    'bfe': 'служба базовой фильтрации (основа брандмауэра)',
    'mpssvc': 'сам брандмауэр Защитника Windows',
}


class FirewallError(Exception):
    pass


_ENV_RE = re.compile(r'%([^%]+)%')


def normalize_path(path):
    """Путь для сравнения: переменные %SystemRoot% раскрыты, регистр не важен."""
    path = (path or '').strip().strip('"')
    path = _ENV_RE.sub(lambda m: os.environ.get(m.group(1), os.environ.get(m.group(1).upper(), m.group(0))), path)
    return path.replace('/', '\\').lower()


def split_services(text):
    return [s.strip() for s in re.split(r'[,;\s]+', text or '') if s.strip()]


def entry_key(program, service):
    return (normalize_path(program), (service or '').lower())


def rule_id(program, service, direction):
    raw = '%s|%s|%s' % (normalize_path(program), (service or '').lower(), direction)
    return 'NetMon-' + hashlib.sha1(raw.encode('utf-8')).hexdigest()[:16]


def rule_display_name(program, service, direction):
    what = ntpath.basename(program) or program
    if service:
        what += ' (служба %s)' % service
    return 'NetMon: запрет %s — %s' % ('исходящих' if direction == 'out' else 'входящих', what)


def block_plan(program, services=(), directions=('out', 'in')):
    """Описания правил, которые нужно создать."""
    created = time.strftime('%d.%m.%Y %H:%M')
    plan = []
    for service in list(services) or ['']:
        for direction in directions:
            plan.append({
                'id': rule_id(program, service, direction),
                'name': rule_display_name(program, service, direction),
                'direction': DIRECTIONS[direction],
                'program': program,
                'service': service,
                'description': 'Создано программой «Сетевая активность программ» %s' % created,
            })
    return plan


def stale_rule_ids(entries, plan):
    """Правила той же программы (и служб), которых нет в новом плане: их нужно убрать,
    чтобы новый выбор («только исходящие» вместо «всё») заменил старый."""
    keys = {entry_key(p['program'], p['service']) for p in plan}
    new_ids = {p['id'] for p in plan}
    return [i for e in entries if e.key in keys for i in e.rule_ids if i not in new_ids]


def check_blockable(program, services, pid=None):
    """Текст ошибки, если такую программу запрещать нельзя, иначе None."""
    if pid in (0, 4) or (program or '').strip().lower() == 'system':
        return ('Это ядро Windows (System). Через него идут общие папки и служебный '
                'трафик; запрет сломал бы сеть, поэтому он недоступен.')
    if not (program or '').strip():
        return 'Не указан файл программы. Выберите .exe кнопкой «Обзор…».'
    if not ntpath.isabs(program.strip().strip('"')):
        return 'Нужен полный путь к файлу программы, например C:\\Program Files\\...\\app.exe.'
    if ntpath.basename(normalize_path(program)) == 'svchost.exe' and not services:
        return ('svchost.exe — общий процесс для служб Windows. Запрет его целиком отрежет от '
                'сети почти всю систему. Укажите, каким службам запретить сеть.')
    return None


def warnings_for(program, services):
    """Предупреждения, которые стоит показать перед созданием правил."""
    result = []
    base = ntpath.basename(normalize_path(program))
    for service in services:
        why = CRITICAL_SERVICES.get(service.lower())
        if why:
            result.append('Служба %s — %s.' % (service, why))
    if base in ('python.exe', 'pythonw.exe', 'py.exe', 'pyw.exe'):
        result.append('Правило запретит сеть всем скриптам, запущенным этим Python.')
    if base == 'explorer.exe':
        result.append('Проводник перестанет загружать новости, погоду и прочее из интернета. '
                      'Работа с файлами и общими папками не пострадает.')
    if '\\windowsapps\\' in normalize_path(program):
        result.append('Это приложение из Microsoft Store: после его обновления путь изменится '
                      'и правило придётся создать заново.')
    return result


def group_rules(rules):
    """Правила -> строки списка (одна строка на программу или службу)."""
    groups = {}
    order = []
    for rule in rules:
        key = entry_key(rule.program, rule.service)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(rule)
    entries = []
    for key in order:
        items = groups[key]
        states = {r.enabled for r in items}
        entries.append(Entry(
            key=key, program=items[0].program, service=items[0].service,
            directions=tuple(d for d in ('out', 'in') if any(r.direction == d for r in items)),
            enabled=states.pop() if len(states) == 1 else None,
            rule_ids=tuple(r.id for r in items)))
    return entries


def directions_label(directions):
    if set(directions) == {'out', 'in'}:
        return 'исходящие и входящие'
    if directions == ('out',):
        return 'исходящие'
    if directions == ('in',):
        return 'входящие'
    return ''


# ------------------------------------------------------------------ PowerShell

_PRELUDE = r"""
$ProgressPreference = 'SilentlyContinue'
$ErrorActionPreference = 'Stop'
function Send-Result($obj) {
    $json = ConvertTo-Json -InputObject $obj -Depth 5 -Compress
    [Console]::Out.Write('NETMON-OK:' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([string]$json)))
}
try {
    $data = ConvertFrom-Json ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%DATA%')))
%BODY%
} catch {
    [Console]::Out.Write('NETMON-ERR:' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([string]$_.Exception.Message)))
    exit 1
}
"""

_LIST_BODY = r"""
    $rules = New-Object System.Collections.Generic.List[object]
    foreach ($r in @(Get-NetFirewallRule -Group '%GROUP%' -ErrorAction SilentlyContinue)) {
        if ($null -eq $r) { continue }
        $app = Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $r
        $svc = Get-NetFirewallServiceFilter -AssociatedNetFirewallRule $r
        $rules.Add([pscustomobject]@{
            id = [string]$r.Name; name = [string]$r.DisplayName
            direction = [string]$r.Direction; action = [string]$r.Action
            enabled = ([string]$r.Enabled -eq 'True')
            program = [string]$app.Program; service = [string]$svc.Service })
    }
    $profiles = New-Object System.Collections.Generic.List[object]
    foreach ($p in @(Get-NetFirewallProfile -PolicyStore ActiveStore)) {
        $profiles.Add([pscustomobject]@{ name = [string]$p.Name; enabled = ([string]$p.Enabled -ne 'False') })
    }
    Send-Result ([pscustomobject]@{ rules = $rules.ToArray(); profiles = $profiles.ToArray() })
"""

_ADD_BODY = r"""
    foreach ($i in @($data)) {
        Remove-NetFirewallRule -Name $i.id -ErrorAction SilentlyContinue
        $params = @{ Name = $i.id; DisplayName = $i.name; Group = '%GROUP%'
                     Description = $i.description; Direction = $i.direction; Action = 'Block'
                     Program = $i.program; Profile = 'Any'; Enabled = 'True' }
        if ($i.service) { $params['Service'] = $i.service }
        New-NetFirewallRule @params | Out-Null
    }
    Send-Result $true
"""

_REMOVE_BODY = r"""
    foreach ($id in @($data)) { Remove-NetFirewallRule -Name $id -ErrorAction SilentlyContinue }
    Send-Result $true
"""

_ENABLE_BODY = r"""
    $state = if ($data.enabled) { 'True' } else { 'False' }
    foreach ($id in @($data.ids)) { Set-NetFirewallRule -Name $id -Enabled $state }
    Send-Result $true
"""


def build_script(body, data=None):
    data = {} if data is None else data
    payload = base64.b64encode(json.dumps(data, ensure_ascii=False).encode('utf-8')).decode('ascii')
    return (_PRELUDE.replace('%BODY%', body.replace('%GROUP%', GROUP))
            .replace('%DATA%', payload))


def _decode_console(raw):
    for encoding in ('utf-8', 'oem', 'cp866'):
        try:
            return raw.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode('latin-1')


def parse_output(stdout, stderr=b'', returncode=0):
    text = stdout.decode('ascii', 'replace')
    for marker, ok in (('NETMON-OK:', True), ('NETMON-ERR:', False)):
        pos = text.rfind(marker)
        if pos < 0:
            continue
        payload = text[pos + len(marker):].strip().split()
        decoded = base64.b64decode(payload[0] if payload else '').decode('utf-8', 'replace')
        if ok:
            return json.loads(decoded)
        raise FirewallError(decoded.strip() or 'неизвестная ошибка PowerShell')
    message = _decode_console(stderr or b'').strip() or _decode_console(stdout).strip()
    raise FirewallError(message or 'PowerShell завершился с кодом %s' % returncode)


def parse_state(result):
    """Ответ скрипта списка -> ([Rule], [(профиль, включён)])."""
    def as_list(value):
        if value is None:
            return []
        return value if isinstance(value, list) else [value]

    rules = []
    for item in as_list((result or {}).get('rules')):
        if not isinstance(item, dict) or item.get('action', 'Block') != 'Block':
            continue
        program = item.get('program') or ''
        service = item.get('service') or ''
        rules.append(Rule(
            id=item.get('id') or '', name=item.get('name') or '',
            direction=_FROM_PS_DIRECTION.get(item.get('direction'), 'out'),
            enabled=bool(item.get('enabled')),
            program='' if program == 'Any' else program,
            service='' if service == 'Any' else service))
    profiles = [(p.get('name') or '?', bool(p.get('enabled')))
                for p in as_list((result or {}).get('profiles')) if isinstance(p, dict)]
    return rules, profiles


class WindowsFirewall:
    """Правила Брандмауэра Защитника Windows (через PowerShell)."""

    def __init__(self, timeout=120, executable=None, prelude=''):
        self.timeout = timeout
        self.executable = executable
        self.prelude = prelude     # для тестов: подмена командлетов

    def _powershell(self):
        if self.executable:
            return self.executable
        root = os.environ.get('SystemRoot', r'C:\Windows')
        path = os.path.join(root, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe')
        return path if os.path.exists(path) else 'powershell.exe'

    def _run(self, body, data=None):
        script = self.prelude + build_script(body, data)
        encoded = base64.b64encode(script.encode('utf-16-le')).decode('ascii')
        args = [self._powershell(), '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
                '-EncodedCommand', encoded]
        try:
            proc = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, timeout=self.timeout,
                                  creationflags=CREATE_NO_WINDOW if sys.platform == 'win32' else 0)
        except FileNotFoundError:
            raise FirewallError('не найден PowerShell (powershell.exe)')
        except subprocess.TimeoutExpired:
            raise FirewallError('PowerShell не ответил за %d с' % self.timeout)
        return parse_output(proc.stdout, proc.stderr, proc.returncode)

    def state(self):
        return parse_state(self._run(_LIST_BODY))

    def add(self, plan):
        self._run(_ADD_BODY, plan)

    def remove(self, ids):
        self._run(_REMOVE_BODY, list(ids))

    def set_enabled(self, ids, enabled):
        self._run(_ENABLE_BODY, {'ids': list(ids), 'enabled': bool(enabled)})


class DemoFirewall:
    """Брандмауэр «понарошку» для демо-режима и тестов: правила хранятся в памяти."""

    def __init__(self, delay=0.3):
        self.delay = delay
        self.rules = {}
        self._lock = threading.Lock()

    def state(self):
        time.sleep(self.delay)
        with self._lock:
            return list(self.rules.values()), [('Domain', True), ('Private', True), ('Public', True)]

    def add(self, plan):
        with self._lock:
            for item in plan:
                self.rules[item['id']] = Rule(item['id'], item['name'],
                                              _FROM_PS_DIRECTION[item['direction']], True,
                                              item['program'], item['service'])

    def remove(self, ids):
        with self._lock:
            for rule_id_ in ids:
                self.rules.pop(rule_id_, None)

    def set_enabled(self, ids, enabled):
        with self._lock:
            for rule_id_ in ids:
                if rule_id_ in self.rules:
                    self.rules[rule_id_] = self.rules[rule_id_]._replace(enabled=bool(enabled))

    def blocks(self, program, services, direction='out'):
        """Заблокирован ли трафик программы (для имитации в демо-режиме)."""
        with self._lock:
            rules = list(self.rules.values())
        keys = {entry_key(program, s) for s in list(services) + ['']}
        return any(r.enabled and r.direction == direction and entry_key(r.program, r.service) in keys
                   for r in rules)


class FirewallManager:
    """Кэш правил и фоновое выполнение команд (PowerShell работает секунды)."""

    def __init__(self, backend):
        self.backend = backend
        self._lock = threading.Lock()
        self._pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix='firewall')
        self.entries = []
        self.profiles = []
        self.loaded = False
        self.busy = 0
        self.version = 0
        self.error = ''
        self._index = {}
        self._messages = []

    # ---- команды (выполняются в фоне, после каждой список перечитывается)

    def refresh(self):
        return self._submit(None, None)

    def block(self, program, services=(), directions=('out', 'in')):
        plan = block_plan(program, services, directions)
        what = ntpath.basename(program) + (' (службы: %s)' % ', '.join(services) if services else '')

        def action():
            stale = stale_rule_ids(group_rules(self.backend.state()[0]), plan)
            if stale:
                self.backend.remove(stale)
            self.backend.add(plan)
        return self._submit(action, 'Запрещено: %s — %s' % (what, directions_label(tuple(directions))))

    def unblock(self, entries):
        ids = [i for e in entries for i in e.rule_ids]
        names = ', '.join(_entry_title(e) for e in entries)
        return self._submit(lambda: self.backend.remove(ids), 'Убрано из списка: %s' % names)

    def set_enabled(self, entries, enabled):
        ids = [i for e in entries for i in e.rule_ids]
        names = ', '.join(_entry_title(e) for e in entries)
        text = ('Снова запрещено: %s' if enabled else 'Временно разрешено: %s') % names
        return self._submit(lambda: self.backend.set_enabled(ids, enabled), text)

    def _submit(self, action, success_text):
        with self._lock:
            self.busy += 1
        return self._pool.submit(self._run, action, success_text)

    def _run(self, action, success_text):
        try:
            if action is not None:
                action()
            rules, profiles = self.backend.state()
            entries = group_rules(rules)
            with self._lock:
                self.entries = entries
                self.profiles = profiles
                self._index = {e.key: e for e in entries}
                self.loaded = True
                self.error = ''
                if success_text:
                    self._messages.append(('info', success_text))
        except Exception as exc:
            log.exception('ошибка брандмауэра')
            with self._lock:
                self.error = str(exc)
                if action is not None:
                    self._messages.append(('error', str(exc)))
        finally:
            with self._lock:
                self.busy -= 1
                self.version += 1

    def take_messages(self):
        with self._lock:
            messages, self._messages = self._messages, []
        return messages

    def shutdown(self):
        try:
            self._pool.shutdown(wait=False, cancel_futures=True)
        except TypeError:  # Python < 3.9
            self._pool.shutdown(wait=False)

    # ---- запросы для интерфейса

    def disabled_profiles(self):
        with self._lock:
            return [name for name, enabled in self.profiles if not enabled]

    def status(self, program, services_text=''):
        """('blocked' | 'partial' | 'allowed' | '', подпись) для строки таблицы процессов."""
        if not program:
            return '', ''
        with self._lock:
            index = self._index
        path = normalize_path(program)
        whole = index.get((path, ''))
        if whole is not None:
            if whole.enabled is True:
                label = {('out',): 'запрещена (исх.)', ('in',): 'запрещена (вх.)'}
                return 'blocked', label.get(whole.directions, 'запрещена')
            if whole.enabled is False:
                return 'allowed', 'запрет выключен'
            return 'partial', 'частично'
        services = split_services(services_text)
        blocked = [s for s in services
                   if getattr(index.get((path, s.lower())), 'enabled', None) is True]
        if blocked and len(blocked) == len(services):
            return 'blocked', 'запрещена'
        if blocked:
            return 'partial', 'частично: %s' % ', '.join(blocked)
        return '', ''

    def entries_for(self, program, services_text=''):
        """Строки списка, относящиеся к программе (для «Разрешить доступ в сеть»)."""
        path = normalize_path(program)
        services = {s.lower() for s in split_services(services_text)}
        with self._lock:
            return [e for e in self.entries
                    if e.key[0] == path and (not e.key[1] or e.key[1] in services)]


def _entry_title(entry):
    name = ntpath.basename(entry.program) or entry.program
    return '%s (%s)' % (name, entry.service) if entry.service else name
