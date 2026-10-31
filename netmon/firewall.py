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


RESERVED_SERVICE_NAMES = {'any', '*', 'all'}
_SERVICE_NAME_RE = re.compile(r'^[^\\/\s,;]{1,256}$')


def service_exists(name):
    """True/False — есть ли служба с таким коротким именем; None, если проверить нельзя."""
    if sys.platform != 'win32':
        return None
    from winapi import service_exists as check
    return check(name)


def check_services(services):
    """Текст ошибки для недопустимых имён служб, иначе None."""
    for service in services:
        if service.lower() in RESERVED_SERVICE_NAMES:
            return ('«%s» — не имя службы: в правилах брандмауэра это значит «все службы». '
                    'Укажите короткое имя конкретной службы, например wuauserv.' % service)
        if not _SERVICE_NAME_RE.match(service):
            return ('Недопустимое имя службы «%s». Нужно короткое имя (как в столбце «Имя» '
                    'оснастки services.msc), например wuauserv.' % service)
        if service_exists(service) is False:
            return 'Служба «%s» в Windows не найдена. Проверьте короткое имя службы.' % service
    return None


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
    return check_services(services)


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


def apply_block(backend, program, services=(), directions=('out', 'in')):
    """Создаёт или обновляет правила запрета, а лишние правила этой программы удаляет
    последними. Если что-то пойдёт не так, прежний запрет останется в силе.

    Возвращает (план, id удалённых лишних правил).
    """
    error = check_blockable(program, services)
    if error:
        raise FirewallError(error)
    plan = block_plan(program, services, directions)
    stale = stale_rule_ids(group_rules(backend.state()[0]), plan)
    backend.add(plan)
    if stale:
        backend.remove(stale)
    return plan, stale


def _rule_matches(rule, item):
    return (rule is not None and rule.enabled
            and rule.direction == _FROM_PS_DIRECTION.get(item['direction'])
            and normalize_path(rule.program) == normalize_path(item['program'])
            and (rule.service or '').lower() == (item['service'] or '').lower())


def _missing_text(rules, plan):
    by_id = {r.id: r for r in rules}
    missing = [item for item in plan if not _rule_matches(by_id.get(item['id']), item)]
    if not missing:
        return None
    return 'Брандмауэр не подтвердил запрет: %s.' % ', '.join(
        '%s — %s' % (_plan_title(item), directions_label((_FROM_PS_DIRECTION[item['direction']],)))
        for item in missing)


def verify_block(rules, plan):
    """Проверка по фактически прочитанным правилам: все правила плана есть и включены,
    а других правил для этих программ (служб) нет. None — всё так, иначе текст проблемы."""
    keys = {entry_key(item['program'], item['service']) for item in plan}
    ids = {item['id'] for item in plan}
    left = [r.id for r in rules if r.id not in ids and entry_key(r.program, r.service) in keys]
    problems = [_missing_text(rules, plan) or '']
    if left:
        problems.append('Не удалось убрать прежние правила (их осталось %d).' % len(left))
    return ' '.join(p for p in problems if p) or None


def verify_present(rules, plan):
    """Все правила плана есть, включены и блокируют (лишние правила не мешают)."""
    return _missing_text(rules, plan)


def verify_removed(rules, ids):
    left = {r.id for r in rules} & set(ids)
    if left:
        return 'Правила не удалены (осталось %d): запрет всё ещё действует.' % len(left)
    return None


def verify_disabled(rules, ids):
    """Временное разрешение: ни одно из этих правил не должно действовать.
    Отсутствующее правило тоже ничего не блокирует, это допустимый итог."""
    wrong = [r for r in rules if r.id in set(ids) and r.enabled]
    if wrong:
        return 'Брандмауэр не подтвердил изменение: правил всё ещё действует %d.' % len(wrong)
    return None


def entries_plan(entries):
    """План правил, восстанавливающий запреты этих строк списка целиком."""
    plan = []
    for e in entries:
        plan.extend(block_plan(e.program, [e.service] if e.service else [], e.directions))
    return plan


def describe_state(entries, keys):
    """Как сейчас обстоят дела с запретом для указанных пар (программа, служба)."""
    found = [e for e in entries if e.key in keys]
    if not found:
        return 'Сейчас запрета нет.'
    parts = []
    for e in found:
        state = {True: 'действует', False: 'выключен'}.get(e.enabled, 'действует частично')
        parts.append('%s — %s, %s' % (_entry_title(e), directions_label(e.directions), state))
    return 'Сейчас запрет: %s.' % '; '.join(parts)


def _plan_title(item):
    name = ntpath.basename(item['program']) or item['program']
    return '%s (%s)' % (name, item['service']) if item['service'] else name


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
# Правила по фильтру (@{ Group = ... } или @{ Name = ... }). «Не найдено» — это просто
# пустой результат; любая другая ошибка чтения (нет доступа и т.п.) прерывает скрипт,
# чтобы она не выглядела как «правил нет».
function Find-NetMonRules([hashtable]$Filter) {
    $problems = $null
    $found = @(Get-NetFirewallRule @Filter -ErrorAction SilentlyContinue -ErrorVariable problems |
               Where-Object { $null -ne $_ })
    foreach ($e in @($problems)) {
        if ($null -eq $e) { continue }
        $notFound = ([string]$e.CategoryInfo.Category -eq 'ObjectNotFound') -or
                    ([string]$e.FullyQualifiedErrorId -like 'CmdletizationQuery_NotFound*')
        if (-not $notFound) { throw $e.Exception }
    }
    $found
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
    foreach ($r in @(Find-NetMonRules @{ Group = '%GROUP%' })) {
        $app = Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $r -ErrorAction Stop
        $svc = Get-NetFirewallServiceFilter -AssociatedNetFirewallRule $r -ErrorAction Stop
        $rules.Add([pscustomobject]@{
            id = [string]$r.Name; name = [string]$r.DisplayName
            direction = [string]$r.Direction; action = [string]$r.Action
            enabled = ([string]$r.Enabled -eq 'True')
            program = [string]$app.Program; service = [string]$svc.Service })
    }
    $profiles = New-Object System.Collections.Generic.List[object]
    foreach ($p in @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)) {
        $profiles.Add([pscustomobject]@{ name = [string]$p.Name; enabled = ([string]$p.Enabled -ne 'False') })
    }
    Send-Result ([pscustomobject]@{ rules = $rules.ToArray(); profiles = $profiles.ToArray() })
"""

# Существующее правило обновляется на месте, новое создаётся; ничего не удаляется,
# поэтому ошибка посередине не снимает прежний запрет.
_ADD_BODY = r"""
    foreach ($i in @($data)) {
        if ([string]::IsNullOrWhiteSpace([string]$i.program)) { throw 'не указан путь к программе' }
        if ($i.service -and (@('any', '*', 'all') -contains ([string]$i.service).ToLowerInvariant())) {
            throw ('недопустимое имя службы: ' + $i.service)
        }
        $existing = @(Find-NetMonRules @{ Name = $i.id })
        if ($existing.Count -gt 0) {
            Set-NetFirewallRule -Name $i.id -Direction $i.direction -Action Block -Profile Any -Enabled True -ErrorAction Stop
            $app = Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $existing[0] -ErrorAction Stop
            if ([string]$app.Program -ne [string]$i.program) {
                $app | Set-NetFirewallApplicationFilter -Program $i.program -ErrorAction Stop
            }
            $wantService = if ($i.service) { [string]$i.service } else { 'Any' }
            $svc = Get-NetFirewallServiceFilter -AssociatedNetFirewallRule $existing[0] -ErrorAction Stop
            if ([string]$svc.Service -ne $wantService) {
                $svc | Set-NetFirewallServiceFilter -Service $wantService -ErrorAction Stop
            }
        } else {
            $params = @{ Name = $i.id; DisplayName = $i.name; Group = '%GROUP%'
                         Description = $i.description; Direction = $i.direction; Action = 'Block'
                         Program = $i.program; Profile = 'Any'; Enabled = 'True' }
            if ($i.service) { $params['Service'] = $i.service }
            New-NetFirewallRule @params -ErrorAction Stop | Out-Null
        }
    }
    Send-Result $true
"""

# Отсутствующее правило пропускается; любая другая ошибка чтения или удаления прерывает скрипт.
_REMOVE_BODY = r"""
    foreach ($id in @($data)) {
        $found = @(Find-NetMonRules @{ Name = $id })
        if ($found.Count -eq 0) { continue }
        Remove-NetFirewallRule -Name $id -ErrorAction Stop
    }
    Send-Result $true
"""

_ENABLE_BODY = r"""
    $state = if ($data.enabled) { 'True' } else { 'False' }
    foreach ($id in @($data.ids)) {
        $found = @(Find-NetMonRules @{ Name = $id })
        if ($found.Count -eq 0) { continue }
        Set-NetFirewallRule -Name $id -Enabled $state -ErrorAction Stop
    }
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
        self.loaded = False        # правила хоть раз прочитаны
        self.state_known = False   # кэш совпадает с последним успешным чтением
        self.busy = 0
        self.version = 0
        self.error = ''
        self._index = {}
        self._uncertain = set()    # (программа, служба), состояние которых сейчас неизвестно
        self._messages = []

    # ---- команды (выполняются в фоне, после каждой список перечитывается)

    def refresh(self):
        return self._submit(None, None, None, ())

    def block(self, program, services=(), directions=('out', 'in')):
        services, directions = list(services), tuple(directions)
        what = ntpath.basename(program) + (' (службы: %s)' % ', '.join(services) if services else '')
        result = {}

        def action():
            result['plan'], result['stale'] = apply_block(self.backend, program, services, directions)

        def verify(rules):
            return verify_block(rules, result.get('plan') or block_plan(program, services, directions))
        keys = {entry_key(program, s) for s in services or ['']}
        return self._submit(action, 'Запрещено: %s — %s' % (what, directions_label(directions)),
                            verify, keys)

    def unblock(self, entries):
        ids = [i for e in entries for i in e.rule_ids]
        names = ', '.join(_entry_title(e) for e in entries)
        return self._submit(lambda: self.backend.remove(ids), 'Убрано из списка: %s' % names,
                            lambda rules: verify_removed(rules, ids), {e.key for e in entries})

    def set_enabled(self, entries, enabled):
        names = ', '.join(_entry_title(e) for e in entries)
        keys = {e.key for e in entries}
        if enabled:
            # «Снова запретить» = создать или обновить ВСЕ правила этих строк: если какое-то
            # успели удалить (например, в wf.msc), оно будет восстановлено, а не пропущено
            plan = entries_plan(entries)
            return self._submit(lambda: self.backend.add(plan), 'Снова запрещено: %s' % names,
                                lambda rules: verify_present(rules, plan), keys)
        ids = [i for e in entries for i in e.rule_ids]
        return self._submit(lambda: self.backend.set_enabled(ids, False),
                            'Временно разрешено: %s' % names,
                            lambda rules: verify_disabled(rules, ids), keys)

    def _submit(self, action, success_text, verify, keys):
        with self._lock:
            self.busy += 1
        return self._pool.submit(self._run, action, success_text, verify, set(keys))

    def _run(self, action, success_text, verify, keys):
        """Выполняет команду и ВСЕГДА перечитывает правила: показывается то, что есть на деле."""
        try:
            action_error = None
            if action is not None:
                try:
                    action()
                except Exception as exc:
                    action_error = exc
                    log.warning('команда брандмауэра не выполнена: %s', exc)
            try:
                rules, profiles = self.backend.state()
            except Exception as exc:
                log.exception('не удалось прочитать правила брандмауэра')
                with self._lock:
                    self.state_known = False
                    self._uncertain.update(keys)
                    self.error = 'не удалось прочитать правила: %s' % exc
                    if action is not None:
                        if action_error is not None and str(action_error) == str(exc):
                            text = 'Команда не выполнена: %s.' % exc
                        elif action_error is not None:
                            text = '%s\n\nПроверить результат не удалось: %s.' % (action_error, exc)
                        else:
                            text = 'Команда выполнена, но проверить результат не удалось: %s.' % exc
                        self._messages.append(('error', text + '\n\nСостояние запрета неизвестно.'))
                return
            entries = group_rules(rules)
            problem = verify(rules) if verify is not None else None
            with self._lock:
                self.entries = entries
                self.profiles = profiles
                self._index = {e.key: e for e in entries}
                self.loaded = True
                self.state_known = True
                self._uncertain.clear()
                self.error = ''
                if action is None:
                    return
                if problem is None:
                    if action_error is not None:
                        log.info('команда сообщила об ошибке, но правила в нужном состоянии')
                    self._messages.append(('info', success_text))
                else:
                    text = str(action_error) if action_error is not None else problem
                    self._messages.append(('error', '%s\n\n%s' % (text, describe_state(entries, keys))))
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
        """('blocked' | 'partial' | 'allowed' | 'unknown' | '', подпись) для таблицы процессов."""
        if not program:
            return '', ''
        with self._lock:
            index = self._index
            known = self.state_known
            uncertain = set(self._uncertain)
        path = normalize_path(program)
        keys = {(path, '')} | {(path, s.lower()) for s in split_services(services_text)}
        if keys & uncertain or (not known and any(k in index for k in keys)):
            return 'unknown', 'неизвестно'
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
