"""Брандмауэр: план правил, разбор ответов, статусы и сами скрипты PowerShell.

Скрипты проверяются настоящим PowerShell (pwsh), если он установлен: командлеты
NetSecurity подменяются функциями, которые хранят правила в JSON-файле.
Путь к pwsh можно задать переменной окружения NETMON_PWSH.
"""

import argparse
import base64
import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import firewall  # noqa: E402
from console import run_firewall_cli  # noqa: E402
from firewall import (DemoFirewall, FirewallError, FirewallManager, Rule,  # noqa: E402
                      WindowsFirewall, apply_block, block_plan, check_blockable, check_services,
                      group_rules, normalize_path, parse_output, parse_state, rule_id,
                      verify_block, warnings_for)

EXPLORER = r'C:\Windows\explorer.exe'
SVCHOST = r'C:\Windows\System32\svchost.exe'


def ok_output(obj):
    return ('noise\r\nNETMON-OK:' + base64.b64encode(json.dumps(obj).encode()).decode()).encode()


class PlanTest(unittest.TestCase):
    def test_rule_ids_are_stable_and_case_insensitive(self):
        self.assertEqual(rule_id(EXPLORER, '', 'out'), rule_id(EXPLORER.upper(), '', 'out'))
        self.assertNotEqual(rule_id(EXPLORER, '', 'out'), rule_id(EXPLORER, '', 'in'))
        self.assertNotEqual(rule_id(SVCHOST, 'BITS', 'out'), rule_id(SVCHOST, 'wuauserv', 'out'))
        self.assertTrue(rule_id(EXPLORER, '', 'out').startswith('NetMon-'))

    def test_normalize_path(self):
        os.environ['NETMON_TEST_ROOT'] = r'C:\Windows'
        self.assertEqual(normalize_path(r'%NETMON_TEST_ROOT%\Explorer.EXE'), r'c:\windows\explorer.exe')
        self.assertEqual(normalize_path('"C:/X/y.exe"'), r'c:\x\y.exe')

    def test_block_plan(self):
        plan = block_plan(EXPLORER)
        self.assertEqual([p['direction'] for p in plan], ['Outbound', 'Inbound'])
        self.assertEqual({p['service'] for p in plan}, {''})
        plan = block_plan(SVCHOST, ['BITS', 'wuauserv'], ('out',))
        self.assertEqual([(p['service'], p['direction']) for p in plan],
                         [('BITS', 'Outbound'), ('wuauserv', 'Outbound')])
        self.assertIn('BITS', plan[0]['name'])

    def test_check_blockable(self):
        self.assertIsNone(check_blockable(EXPLORER, []))
        self.assertIn('ядро', check_blockable(r'C:\Windows\System32\ntoskrnl.exe', [], pid=4))
        self.assertIn('svchost', check_blockable(SVCHOST, []))
        self.assertIsNone(check_blockable(SVCHOST, ['BITS']))
        self.assertIsNotNone(check_blockable('', []))
        self.assertIsNotNone(check_blockable('explorer.exe', []))

    def test_reserved_and_invalid_service_names(self):
        # «Any» в правиле брандмауэра означает «все службы» — это запрет svchost целиком
        for bad in ('Any', 'any', '*', 'ALL', 'a b', 'x/y', 'x\\y', ''):
            self.assertIsNotNone(check_services([bad]), bad)
            self.assertIsNotNone(check_blockable(SVCHOST, [bad]), bad)
        self.assertIsNone(check_services(['wuauserv', 'CDPUserSvc_4f2a1', 'BITS']))

    def test_warnings(self):
        self.assertTrue(any('Dnscache' in w for w in warnings_for(SVCHOST, ['Dnscache'])))
        self.assertTrue(warnings_for(EXPLORER, []))
        self.assertEqual(warnings_for(r'C:\Games\game.exe', []), [])


class ParseTest(unittest.TestCase):
    def test_parse_output(self):
        self.assertEqual(parse_output(ok_output({'a': 1})), {'a': 1})
        err = ('NETMON-ERR:' + base64.b64encode('Отказано в доступе.'.encode()).decode()).encode()
        with self.assertRaisesRegex(FirewallError, 'Отказано'):
            parse_output(err, b'', 1)
        with self.assertRaisesRegex(FirewallError, 'boom'):
            parse_output(b'', b'boom', 1)

    def test_parse_state_and_grouping(self):
        result = {'rules': [
            {'id': 'a', 'name': 'x', 'direction': 'Outbound', 'enabled': True, 'action': 'Block',
             'program': EXPLORER, 'service': 'Any'},
            {'id': 'b', 'name': 'x', 'direction': 'Inbound', 'enabled': False, 'action': 'Block',
             'program': EXPLORER.lower(), 'service': 'Any'},
            {'id': 'c', 'name': 'y', 'direction': 'Outbound', 'enabled': True, 'action': 'Allow',
             'program': EXPLORER, 'service': 'Any'},
        ], 'profiles': {'name': 'Public', 'enabled': False}}
        rules, profiles = parse_state(result)
        self.assertEqual([r.id for r in rules], ['a', 'b'])
        self.assertEqual(rules[0].service, '')
        self.assertEqual(profiles, [('Public', False)])
        (entry,) = group_rules(rules)
        self.assertEqual((entry.directions, entry.enabled, entry.rule_ids), (('out', 'in'), None, ('a', 'b')))


class ScriptedFirewall(DemoFirewall):
    """DemoFirewall, которому можно подстроить сбои, как у настоящего брандмауэра."""

    def __init__(self):
        super().__init__(delay=0)
        self.fail_add_after = None      # сколько правил успеть создать до ошибки
        self.fail_remove = False
        self.silent_remove = False      # «успешно», но ничего не удалено
        self.fail_state = False

    def state(self):
        if self.fail_state:
            raise FirewallError('PowerShell не ответил')
        return super().state()

    def add(self, plan):
        if self.fail_add_after is not None:
            super().add(plan[:self.fail_add_after])
            raise FirewallError('Отказано в доступе.')
        super().add(plan)

    def remove(self, ids):
        if self.fail_remove:
            raise FirewallError('Access denied removing rule')
        if not self.silent_remove:
            super().remove(ids)


class ManagerTest(unittest.TestCase):
    def setUp(self):
        firewall.log.disabled = True
        self.addCleanup(setattr, firewall.log, 'disabled', False)
        self.backend = ScriptedFirewall()
        self.m = FirewallManager(self.backend)
        self.addCleanup(self.m.shutdown)

    def directions(self, program, service=''):
        return {r.direction for r in self.backend.rules.values()
                if normalize_path(r.program) == normalize_path(program) and r.service == service}

    def test_block_status_unblock(self):
        self.m.refresh().result()
        self.assertEqual(self.m.status(EXPLORER), ('', ''))
        self.m.block(EXPLORER).result()
        self.assertEqual(self.m.status(EXPLORER.upper()), ('blocked', 'запрещена'))
        self.assertTrue(self.backend.blocks(EXPLORER, []))
        self.assertEqual(self.m.take_messages()[0][0], 'info')
        self.m.set_enabled(self.m.entries, False).result()
        self.assertEqual(self.m.status(EXPLORER)[0], 'allowed')
        self.assertFalse(self.backend.blocks(EXPLORER, []))
        self.m.unblock(self.m.entries_for(EXPLORER)).result()
        self.assertEqual(self.m.entries, [])
        self.assertEqual(self.m.busy, 0)

    def test_new_choice_replaces_old_one(self):
        self.m.block(EXPLORER).result()
        self.m.block(EXPLORER, (), ('out',)).result()
        (entry,) = self.m.entries
        self.assertEqual(entry.directions, ('out',))
        self.m.block(SVCHOST, ['BITS'], ('out',)).result()
        self.m.block(SVCHOST, ['wuauserv']).result()   # другая служба — не трогаем BITS
        self.assertEqual(sorted(e.service for e in self.m.entries), ['', 'BITS', 'wuauserv'])

    def test_services(self):
        self.m.block(SVCHOST, ['BITS'], ('out',)).result()
        self.assertEqual(self.m.status(SVCHOST, 'BITS, wuauserv'), ('partial', 'частично: BITS'))
        self.assertEqual(self.m.status(SVCHOST, 'BITS'), ('blocked', 'запрещена'))
        self.assertEqual(self.m.status(SVCHOST, 'Dnscache'), ('', ''))
        self.assertEqual(len(self.m.entries_for(SVCHOST, 'BITS, wuauserv')), 1)
        self.assertEqual(self.m.entries_for(SVCHOST, 'Dnscache'), [])

    def test_failed_update_keeps_existing_block(self):
        # отчёт, п. 1: было «всё», выбрали «только исходящие», создание правила упало
        self.m.block(EXPLORER).result()
        self.m.take_messages()
        self.backend.fail_add_after = 0
        self.m.block(EXPLORER, (), ('out',)).result()
        self.assertEqual(self.directions(EXPLORER), {'out', 'in'})        # запрет на месте
        self.assertEqual(self.m.status(EXPLORER), ('blocked', 'запрещена'))
        ((kind, text),) = self.m.take_messages()
        self.assertEqual(kind, 'error')
        self.assertIn('Отказано в доступе', text)
        self.assertIn('исходящие и входящие, действует', text)

    def test_partial_failure_shows_actual_state(self):
        self.backend.fail_add_after = 1                                   # успело создаться одно
        self.m.block(EXPLORER).result()
        self.assertEqual(self.directions(EXPLORER), {'out'})
        self.assertEqual(self.m.status(EXPLORER), ('blocked', 'запрещена (исх.)'))
        ((kind, text),) = self.m.take_messages()
        self.assertEqual(kind, 'error')
        self.assertIn('исходящие, действует', text)

    def test_failed_remove_is_reported(self):
        # отчёт, п. 2: отказ удаления не должен выглядеть как «Убрано из списка»
        self.m.block(EXPLORER).result()
        self.m.take_messages()
        self.backend.fail_remove = True
        self.m.unblock(self.m.entries_for(EXPLORER)).result()
        self.assertEqual(self.directions(EXPLORER), {'out', 'in'})
        self.assertEqual(self.m.status(EXPLORER), ('blocked', 'запрещена'))
        ((kind, text),) = self.m.take_messages()
        self.assertEqual(kind, 'error')
        self.assertIn('Access denied', text)

    def test_silently_ignored_remove_is_caught(self):
        self.m.block(EXPLORER).result()
        self.m.take_messages()
        self.backend.silent_remove = True
        self.m.unblock(self.m.entries_for(EXPLORER)).result()
        ((kind, text),) = self.m.take_messages()
        self.assertEqual(kind, 'error')
        self.assertIn('не удалены', text)

    def test_unreadable_state_is_unknown_not_blocked(self):
        self.m.block(EXPLORER).result()
        self.m.take_messages()
        self.backend.fail_state = True
        self.backend.rules.clear()                    # правила исчезли, но прочитать это нельзя
        self.m.block(EXPLORER, (), ('out',)).result()
        self.assertEqual(self.m.status(EXPLORER), ('unknown', 'неизвестно'))
        self.assertFalse(self.m.state_known)
        ((kind, text),) = self.m.take_messages()
        self.assertEqual(kind, 'error')
        self.assertIn('неизвестно', text)
        self.backend.fail_state = False
        self.m.refresh().result()
        self.assertEqual(self.m.status(EXPLORER), ('', ''))           # правда: запрета нет

    def test_reblock_restores_missing_rules(self):
        # отчёт 1.1, R2: пока запрет был временно выключен, исходящее правило удалили снаружи
        self.m.block(EXPLORER).result()
        self.m.set_enabled(self.m.entries, False).result()
        self.m.take_messages()
        selected = list(self.m.entries)                      # строка, выбранная в окне
        self.backend.rules.pop(rule_id(EXPLORER, '', 'out'))
        self.m.set_enabled(selected, True).result()
        self.assertEqual({(r.direction, r.enabled) for r in self.backend.rules.values()},
                         {('out', True), ('in', True)})
        self.assertEqual(self.m.take_messages()[0][0], 'info')
        self.assertEqual(self.m.status(EXPLORER), ('blocked', 'запрещена'))
        self.backend.rules.clear()                           # пропали оба правила
        self.m.set_enabled(selected, True).result()
        self.assertEqual(len(self.backend.rules), 2)

    def test_reblock_failure_is_not_reported_as_success(self):
        self.m.block(EXPLORER).result()
        self.m.set_enabled(self.m.entries, False).result()
        self.m.take_messages()
        selected = list(self.m.entries)
        self.backend.rules.pop(rule_id(EXPLORER, '', 'out'))
        self.backend.fail_add_after = 0
        self.m.set_enabled(selected, True).result()
        ((kind, text),) = self.m.take_messages()
        self.assertEqual(kind, 'error')
        self.assertNotIn('Снова запрещено', text)

    def test_pause_with_missing_rule_is_fine(self):
        self.m.block(EXPLORER).result()
        self.m.take_messages()
        selected = list(self.m.entries)
        self.backend.rules.pop(rule_id(EXPLORER, '', 'in'))
        self.m.set_enabled(selected, False).result()
        self.assertEqual(self.m.take_messages()[0][0], 'info')
        self.assertEqual({r.enabled for r in self.backend.rules.values()}, {False})

    def test_reserved_service_is_rejected_without_changes(self):
        self.m.block(SVCHOST, ['Any']).result()
        self.assertEqual(self.backend.rules, {})
        ((kind, text),) = self.m.take_messages()
        self.assertEqual(kind, 'error')
        self.assertIn('все службы', text)

    def test_apply_block_order(self):
        calls = []
        backend = self.backend
        orig_add, orig_remove = backend.add, backend.remove
        backend.add = lambda plan: (calls.append('add'), orig_add(plan))
        backend.remove = lambda ids: (calls.append('remove'), orig_remove(ids))
        apply_block(backend, EXPLORER)
        apply_block(backend, EXPLORER, (), ('out',))
        self.assertEqual(calls, ['add', 'add', 'remove'])               # лишнее — только после
        rules = backend.state()[0]
        self.assertIsNone(verify_block(rules, block_plan(EXPLORER, (), ('out',))))
        self.assertIsNotNone(verify_block(rules, block_plan(EXPLORER)))


class CliTest(unittest.TestCase):
    def run_cli(self, backend, **kwargs):
        args = argparse.Namespace(block=None, unblock=None, service=[], outbound_only=False,
                                  blocked=False)
        for key, value in kwargs.items():
            setattr(args, key, value)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = run_firewall_cli(backend, args)
        return code, out.getvalue()

    def test_failed_update_keeps_block_in_cli(self):
        backend = ScriptedFirewall()
        self.assertEqual(self.run_cli(backend, block=EXPLORER)[0], 0)
        backend.fail_add_after = 0
        code, out = self.run_cli(backend, block=EXPLORER, outbound_only=True)
        self.assertEqual(code, 1)
        self.assertIn('Отказано в доступе', out)
        self.assertIn('исходящие и входящие, действует', out)
        self.assertEqual(len(backend.rules), 2)

    def test_failed_unblock_in_cli(self):
        backend = ScriptedFirewall()
        self.run_cli(backend, block=EXPLORER)
        backend.silent_remove = True
        code, out = self.run_cli(backend, unblock=EXPLORER)
        self.assertEqual(code, 1)
        self.assertIn('не удалены', out)
        self.assertNotIn('Запрет снят', out)
        backend.silent_remove = False
        code, out = self.run_cli(backend, unblock=EXPLORER)
        self.assertEqual(code, 0)
        self.assertIn('Запрет снят', out)
        self.assertEqual(backend.rules, {})


FAKE_CMDLETS = r"""
function Load-Store { if (Test-Path $env:FAKE_FW_STORE) { @(Get-Content -Raw -Encoding UTF8 $env:FAKE_FW_STORE | ConvertFrom-Json) } else { @() } }
function Save-Store($items) { ConvertTo-Json -InputObject @($items) -Depth 4 | Set-Content -Encoding UTF8 $env:FAKE_FW_STORE }
function Get-NetFirewallRule { [CmdletBinding()] param([string]$Group, [string]$Name)
    if ($env:FAKE_FW_DENY_READ) { Write-Error -Category PermissionDenied 'Access denied reading rules'; return }
    if ($Name) { $found = @(Load-Store | Where-Object { $_.Name -eq $Name }) }
    else { $found = @(Load-Store | Where-Object { $_.Group -eq $Group }) }
    if (-not $found) { Write-Error -Category ObjectNotFound "No MSFT_NetFirewallRule objects found"; return }
    $found }
function Get-NetFirewallApplicationFilter { [CmdletBinding()] param($AssociatedNetFirewallRule)
    [pscustomobject]@{ RuleName = $AssociatedNetFirewallRule.Name
        Program = $(if ($AssociatedNetFirewallRule.Program) { $AssociatedNetFirewallRule.Program } else { 'Any' }) } }
function Get-NetFirewallServiceFilter { [CmdletBinding()] param($AssociatedNetFirewallRule)
    [pscustomobject]@{ RuleName = $AssociatedNetFirewallRule.Name
        Service = $(if ($AssociatedNetFirewallRule.Service) { $AssociatedNetFirewallRule.Service } else { 'Any' }) } }
function Set-NetFirewallApplicationFilter { [CmdletBinding()] param([Parameter(ValueFromPipeline = $true)]$InputObject, $Program)
    process { $all = @(Load-Store); foreach ($r in $all) { if ($r.Name -eq $InputObject.RuleName) { $r.Program = $Program } }; Save-Store $all } }
function Set-NetFirewallServiceFilter { [CmdletBinding()] param([Parameter(ValueFromPipeline = $true)]$InputObject, $Service)
    process { $all = @(Load-Store); foreach ($r in $all) { if ($r.Name -eq $InputObject.RuleName) { $r.Service = $(if ($Service -eq 'Any') { '' } else { $Service }) } }; Save-Store $all } }
function Get-NetFirewallProfile { [CmdletBinding()] param([string]$PolicyStore)
    [pscustomobject]@{ Name = 'Domain'; Enabled = 'True' }
    [pscustomobject]@{ Name = 'Private'; Enabled = 'True' }
    [pscustomobject]@{ Name = 'Public'; Enabled = 'False' } }
function New-NetFirewallRule { [CmdletBinding()] param($Name, $DisplayName, $Group, $Description, $Direction, $Action, $Program, $Profile, $Enabled, $Service)
    if ($Program -like '*deny*' -or $env:FAKE_FW_DENY_NEW) { throw 'Отказано в доступе.' }
    Save-Store (@(Load-Store) + [pscustomobject]@{ Name = $Name; DisplayName = $DisplayName; Group = $Group
        Direction = $Direction; Action = $Action; Enabled = $Enabled; Program = $Program; Service = $Service })
    [pscustomobject]@{ Name = $Name } }
function Remove-NetFirewallRule { [CmdletBinding()] param($Name)
    if ($env:FAKE_FW_DENY_REMOVE) { Write-Error -Category PermissionDenied 'Access denied removing rule'; return }
    $all = @(Load-Store); $left = @($all | Where-Object { $_.Name -ne $Name })
    if ($left.Count -eq $all.Count) { Write-Error -Category ObjectNotFound "No MSFT_NetFirewallRule objects found"; return }
    Save-Store $left }
function Set-NetFirewallRule { [CmdletBinding()] param($Name, $Enabled, $Direction, $Action, $Profile)
    if ($env:FAKE_FW_DENY_SET) { throw 'Отказано в доступе (изменение).' }
    $all = @(Load-Store)
    foreach ($r in $all) { if ($r.Name -eq $Name) {
        if ($PSBoundParameters.ContainsKey('Enabled')) { $r.Enabled = [string]$Enabled }
        if ($PSBoundParameters.ContainsKey('Direction')) { $r.Direction = [string]$Direction }
        if ($PSBoundParameters.ContainsKey('Action')) { $r.Action = [string]$Action } } }
    Save-Store $all }
"""

PWSH = os.environ.get('NETMON_PWSH') or shutil.which('pwsh')


@unittest.skipUnless(PWSH, 'PowerShell (pwsh) не найден')
class PowerShellScriptsTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        os.environ['FAKE_FW_STORE'] = os.path.join(self.dir.name, 'rules.json')
        for name in ('FAKE_FW_DENY_NEW', 'FAKE_FW_DENY_REMOVE', 'FAKE_FW_DENY_SET',
                     'FAKE_FW_DENY_READ'):
            os.environ.pop(name, None)
            self.addCleanup(os.environ.pop, name, None)
        self.fw = WindowsFirewall(executable=PWSH, prelude=FAKE_CMDLETS)

    def test_full_cycle_with_unicode_paths(self):
        rules, profiles = self.fw.state()
        self.assertEqual(rules, [])
        self.assertEqual(profiles, [('Domain', True), ('Private', True), ('Public', False)])

        odd = r"C:\Users\Костя\AppData\Local\Program’s 'x' $(calc) & \"q\"\app.exe"
        self.fw.add(block_plan(odd))
        self.fw.add(block_plan(SVCHOST, ['BITS'], ('out',)))
        self.fw.add(block_plan(odd))   # повторный запрет не плодит дубликаты
        rules, _ = self.fw.state()
        self.assertEqual(len(rules), 3)
        by_id = {r.id: r for r in rules}
        rule = by_id[rule_id(odd, '', 'out')]
        self.assertEqual((rule.program, rule.service, rule.enabled, rule.direction), (odd, '', True, 'out'))
        self.assertIn('app.exe', rule.name)
        self.assertEqual(by_id[rule_id(SVCHOST, 'BITS', 'out')].service, 'BITS')

        self.fw.set_enabled([rule_id(odd, '', 'out'), rule_id(odd, '', 'in')], False)
        rules, _ = self.fw.state()
        self.assertEqual({r.enabled for r in rules if r.program == odd}, {False})
        self.fw.add(block_plan(odd))   # повторный запрет включает выключенные правила
        rules, _ = self.fw.state()
        self.assertEqual({r.enabled for r in rules if r.program == odd}, {True})

        self.fw.remove([rule_id(odd, '', 'out'), rule_id(odd, '', 'in'), 'NetMon-missing'])
        rules, _ = self.fw.state()
        self.assertEqual([r.service for r in rules], ['BITS'])
        entries = group_rules(rules)
        self.assertEqual(entries[0].directions, ('out',))

    def test_errors_come_back_readable(self):
        with self.assertRaisesRegex(FirewallError, 'Отказано в доступе'):
            self.fw.add(block_plan(r'C:\deny\app.exe'))

    def test_failed_update_does_not_remove_rules(self):
        # отчёт, п. 1: ошибка при изменении не должна снимать действующий запрет
        self.fw.add(block_plan(EXPLORER))
        os.environ['FAKE_FW_DENY_NEW'] = '1'
        os.environ['FAKE_FW_DENY_SET'] = '1'
        with self.assertRaises(FirewallError):
            apply_block(self.fw, EXPLORER, (), ('out',))
        rules, _ = self.fw.state()
        self.assertEqual({r.direction for r in rules}, {'out', 'in'})

    def test_remove_errors_are_not_swallowed(self):
        # отчёт, п. 2: отказ удаления — ошибка; отсутствующее правило — не ошибка
        self.fw.add(block_plan(EXPLORER))
        os.environ['FAKE_FW_DENY_REMOVE'] = '1'
        with self.assertRaisesRegex(FirewallError, 'Access denied'):
            self.fw.remove([rule_id(EXPLORER, '', 'out')])
        self.assertEqual(len(self.fw.state()[0]), 2)
        os.environ.pop('FAKE_FW_DENY_REMOVE')
        self.fw.remove(['NetMon-missing', rule_id(EXPLORER, '', 'out')])
        self.assertEqual([r.direction for r in self.fw.state()[0]], ['in'])

    def test_read_errors_are_not_treated_as_no_rules(self):
        # отчёт 1.1, R1: отказ чтения правил при рабочем чтении профилей — это ошибка
        self.fw.add(block_plan(EXPLORER))
        os.environ['FAKE_FW_DENY_READ'] = '1'
        for call in (self.fw.state, lambda: self.fw.remove([rule_id(EXPLORER, '', 'out')]),
                     lambda: self.fw.set_enabled([rule_id(EXPLORER, '', 'out')], False),
                     lambda: self.fw.add(block_plan(EXPLORER))):
            with self.assertRaisesRegex(FirewallError, 'Access denied reading rules'):
                call()
        os.environ.pop('FAKE_FW_DENY_READ')
        self.assertEqual(len(self.fw.state()[0]), 2)         # ничего не тронуто

    def test_manager_unblock_with_unreadable_rules(self):
        firewall.log.disabled = True
        self.addCleanup(setattr, firewall.log, 'disabled', False)
        manager = FirewallManager(self.fw)
        self.addCleanup(manager.shutdown)
        manager.block(EXPLORER).result()
        manager.take_messages()
        entries = manager.entries_for(EXPLORER)
        os.environ['FAKE_FW_DENY_READ'] = '1'
        manager.unblock(entries).result()
        os.environ.pop('FAKE_FW_DENY_READ')
        ((kind, text),) = manager.take_messages()
        self.assertEqual(kind, 'error')
        self.assertNotIn('Убрано', text)
        self.assertFalse(manager.state_known)
        self.assertEqual(manager.status(EXPLORER), ('unknown', 'неизвестно'))
        self.assertEqual(len(self.fw.state()[0]), 2)         # правила на месте

    def test_reserved_service_rejected_by_script(self):
        plan = block_plan(SVCHOST, ['Any'], ('out',))
        with self.assertRaisesRegex(FirewallError, 'недопустимое имя службы'):
            self.fw.add(plan)
        self.assertEqual(self.fw.state()[0], [])

    def test_single_rule_is_still_a_list(self):
        self.fw.add(block_plan(EXPLORER, (), ('out',)))
        rules, _ = self.fw.state()
        self.assertEqual([r.direction for r in rules], ['out'])
        self.assertIsInstance(rules[0], Rule)


if __name__ == '__main__':
    unittest.main()
