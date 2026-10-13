"""Брандмауэр: план правил, разбор ответов, статусы и сами скрипты PowerShell.

Скрипты проверяются настоящим PowerShell (pwsh), если он установлен: командлеты
NetSecurity подменяются функциями, которые хранят правила в JSON-файле.
Путь к pwsh можно задать переменной окружения NETMON_PWSH.
"""

import base64
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import firewall  # noqa: E402
from firewall import (DemoFirewall, FirewallError, FirewallManager, Rule,  # noqa: E402
                      WindowsFirewall, block_plan, check_blockable, group_rules, normalize_path,
                      parse_output, parse_state, rule_id, warnings_for)

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


class ManagerTest(unittest.TestCase):
    def setUp(self):
        self.backend = DemoFirewall(delay=0)
        self.m = FirewallManager(self.backend)
        self.addCleanup(self.m.shutdown)

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

    def test_errors_are_reported(self):
        firewall.log.disabled = True
        self.addCleanup(setattr, firewall.log, 'disabled', False)

        def fail(plan):
            raise FirewallError('Отказано в доступе.')
        self.backend.add = fail
        self.m.block(EXPLORER).result()
        self.assertEqual(self.m.take_messages(), [('error', 'Отказано в доступе.')])


FAKE_CMDLETS = r"""
function Load-Store { if (Test-Path $env:FAKE_FW_STORE) { @(Get-Content -Raw -Encoding UTF8 $env:FAKE_FW_STORE | ConvertFrom-Json) } else { @() } }
function Save-Store($items) { ConvertTo-Json -InputObject @($items) -Depth 4 | Set-Content -Encoding UTF8 $env:FAKE_FW_STORE }
function Get-NetFirewallRule { [CmdletBinding()] param([string]$Group)
    $found = @(Load-Store | Where-Object { $_.Group -eq $Group })
    if (-not $found) { Write-Error "No MSFT_NetFirewallRule objects found with property 'Group' equal to '$Group'"; return }
    $found }
function Get-NetFirewallApplicationFilter { [CmdletBinding()] param($AssociatedNetFirewallRule)
    [pscustomobject]@{ Program = $(if ($AssociatedNetFirewallRule.Program) { $AssociatedNetFirewallRule.Program } else { 'Any' }) } }
function Get-NetFirewallServiceFilter { [CmdletBinding()] param($AssociatedNetFirewallRule)
    [pscustomobject]@{ Service = $(if ($AssociatedNetFirewallRule.Service) { $AssociatedNetFirewallRule.Service } else { 'Any' }) } }
function Get-NetFirewallProfile { [CmdletBinding()] param([string]$PolicyStore)
    [pscustomobject]@{ Name = 'Domain'; Enabled = 'True' }
    [pscustomobject]@{ Name = 'Private'; Enabled = 'True' }
    [pscustomobject]@{ Name = 'Public'; Enabled = 'False' } }
function New-NetFirewallRule { [CmdletBinding()] param($Name, $DisplayName, $Group, $Description, $Direction, $Action, $Program, $Profile, $Enabled, $Service)
    if ($Program -like '*deny*') { throw 'Отказано в доступе.' }
    Save-Store (@(Load-Store) + [pscustomobject]@{ Name = $Name; DisplayName = $DisplayName; Group = $Group
        Direction = $Direction; Action = $Action; Enabled = $Enabled; Program = $Program; Service = $Service })
    [pscustomobject]@{ Name = $Name } }
function Remove-NetFirewallRule { [CmdletBinding()] param($Name)
    $all = @(Load-Store); $left = @($all | Where-Object { $_.Name -ne $Name })
    if ($left.Count -eq $all.Count) { Write-Error "No MSFT_NetFirewallRule objects found with property 'Name' equal to '$Name'"; return }
    Save-Store $left }
function Set-NetFirewallRule { [CmdletBinding()] param($Name, $Enabled)
    $all = @(Load-Store); foreach ($r in $all) { if ($r.Name -eq $Name) { $r.Enabled = $Enabled } }; Save-Store $all }
"""

PWSH = os.environ.get('NETMON_PWSH') or shutil.which('pwsh')


@unittest.skipUnless(PWSH, 'PowerShell (pwsh) не найден')
class PowerShellScriptsTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        os.environ['FAKE_FW_STORE'] = os.path.join(self.dir.name, 'rules.json')
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

        self.fw.remove([rule_id(odd, '', 'out'), rule_id(odd, '', 'in'), 'NetMon-missing'])
        rules, _ = self.fw.state()
        self.assertEqual([r.service for r in rules], ['BITS'])
        entries = group_rules(rules)
        self.assertEqual(entries[0].directions, ('out',))

    def test_errors_come_back_readable(self):
        with self.assertRaisesRegex(FirewallError, 'Отказано в доступе'):
            self.fw.add(block_plan(r'C:\deny\app.exe'))

    def test_single_rule_is_still_a_list(self):
        self.fw.add(block_plan(EXPLORER, (), ('out',)))
        rules, _ = self.fw.state()
        self.assertEqual([r.direction for r in rules], ['out'])
        self.assertIsInstance(rules[0], Rule)


if __name__ == '__main__':
    unittest.main()
