"""Модель: учёт байт, направления, имена хостов, жизненный цикл процессов, история."""

import contextlib
import io
import os
import random
import socket
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from model import Model, group_views  # noqa: E402
from monitor import Monitor  # noqa: E402
from storage import Storage  # noqa: E402
from util import RateTracker, fmt_bytes, ip_category, parse_dns_results  # noqa: E402
from winapi import parse_tcp_table_v4, parse_tcp_table_v6  # noqa: E402

LOCAL = '192.168.1.5'
SVCHOST = 'C:\\Windows\\System32\\svchost.exe'


def v4(ip):
    return socket.inet_aton(ip)


def port(n):
    return n.to_bytes(2, 'big')


def traffic(model, pid, remote, rport, lport, sent=0, recv=0, proto='TCP', ts=1000.0,
            local=LOCAL):
    if sent:
        model.on_traffic(pid, proto, True, sent, v4(remote), port(rport), v4(local), port(lport), ts)
    if recv:
        model.on_traffic(pid, proto, False, recv, v4(remote), port(rport), v4(local), port(lport), ts)


def proc_by_pid(model, pid):
    return model.by_pid[pid]


class TrafficTest(unittest.TestCase):
    def setUp(self):
        self.m = Model()
        self.m.resolve_names = False
        self.m.local_ips.add(LOCAL)

    def test_aggregation(self):
        traffic(self.m, 100, '1.2.3.4', 443, 50000, sent=100, recv=1000)
        traffic(self.m, 100, '1.2.3.4', 443, 50001, sent=50, ts=1001)   # другое соединение
        traffic(self.m, 100, '5.6.7.8', 53, 50002, sent=40, recv=80, proto='UDP')
        self.m.process_pending()
        p = proc_by_pid(self.m, 100)
        self.assertEqual((p.sent, p.recv), (190, 1080))
        ep = p.endpoints[('TCP', '1.2.3.4', 443, False)]
        self.assertEqual((ep.sent, ep.recv, ep.psent, ep.precv), (150, 1000, 2, 1))
        self.assertEqual((ep.first, ep.last), (1000.0, 1001))
        self.assertEqual(len(p.endpoints), 2)

    def test_remote_address_is_never_guessed_from_local_list(self):
        # отчёт, п. 7: адрес нового интерфейса (VPN) ещё неизвестен — направление не путается
        self.m.on_traffic(7, 'UDP', False, 60, v4('8.8.8.8'), port(53), v4('10.8.0.2'),
                          port(55000), 1.0)
        self.m.on_traffic(7, 'TCP', True, 10, v4(LOCAL), port(445), v4('10.8.0.2'), port(50000), 1.0)
        self.m.process_pending()
        eps = proc_by_pid(self.m, 7).endpoints
        self.assertEqual(set(eps), {('UDP', '8.8.8.8', 53, False), ('TCP', LOCAL, 445, False)})
        self.assertIn('10.8.0.2', self.m.local_ips)          # адрес сокета запомнен как наш

    def test_own_multicast_echo_is_shown_as_group(self):
        # своё же сообщение в группу 239.255.255.250 вернулось обратно (петля multicast)
        traffic(self.m, 8, '239.255.255.250', 3702, 3702, sent=100, proto='UDP')
        self.m.on_traffic(8, 'UDP', False, 100, v4(LOCAL), port(3702), v4('239.255.255.250'),
                          port(3702), 1000.0)
        self.m.on_traffic(8, 'UDP', False, 50, v4('192.168.1.77'), port(3702),
                          v4('239.255.255.250'), port(3702), 1000.0)
        self.m.process_pending()
        eps = proc_by_pid(self.m, 8).endpoints
        group = eps[('UDP', '239.255.255.250', 3702, False)]
        self.assertEqual((group.sent, group.recv), (100, 100))
        self.assertEqual(eps[('UDP', '192.168.1.77', 3702, False)].recv, 50)  # ответ соседа
        self.assertNotIn('239.255.255.250', self.m.local_ips)

    def test_inbound_by_listen_table_and_accept(self):
        self.m.sync_tcp([(200, 2, '0.0.0.0', 8080, '0.0.0.0', 0)], 0)
        traffic(self.m, 200, '192.168.1.77', 51515, 8080, recv=500)
        traffic(self.m, 200, '140.82.121.4', 443, 50100, sent=5)
        self.m.on_accept(201, port(9000), 1000.0)
        traffic(self.m, 201, '10.0.0.8', 60000, 9000, sent=7)
        self.m.process_pending()
        eps = proc_by_pid(self.m, 200).endpoints
        self.assertIn(('TCP', '192.168.1.77', 8080, True), eps)
        self.assertIn(('TCP', '140.82.121.4', 443, False), eps)
        self.assertIn(('TCP', '10.0.0.8', 9000, True), proc_by_pid(self.m, 201).endpoints)

    def test_udp_direction_heuristic(self):
        traffic(self.m, 300, '192.168.1.40', 55000, 53, recv=60, proto='UDP')    # мы — DNS-сервер
        traffic(self.m, 300, '192.168.1.1', 53, 55001, sent=60, proto='UDP')     # мы — клиент
        self.m.process_pending()
        eps = proc_by_pid(self.m, 300).endpoints
        self.assertIn(('UDP', '192.168.1.40', 53, True), eps)
        self.assertIn(('UDP', '192.168.1.1', 53, False), eps)

    def test_loopback_accounting(self):
        traffic(self.m, 400, '127.0.0.1', 9150, 50000, sent=1000, local='127.0.0.1')
        traffic(self.m, 400, '8.8.8.8', 443, 50001, sent=10)
        self.m.process_pending()
        p = proc_by_pid(self.m, 400)
        self.assertEqual((p.sent, p.lo_sent, p.lo_eps), (1010, 1000, 1))

    def test_search_by_address_respects_localhost_filter(self):
        # отчёт 1.5, п. 9: когда обмен внутри компьютера скрыт, поиск по нему не находит процесс
        traffic(self.m, 10, '127.0.0.1', 8080, 50000, sent=5, local='127.0.0.1')
        traffic(self.m, 11, '93.184.215.14', 443, 50001, sent=5)
        self.m.process_pending()
        uid10, uid11 = proc_by_pid(self.m, 10).uid, proc_by_pid(self.m, 11).uid
        self.assertEqual(self.m.uids_matching_endpoints('127.0.0'), {uid10})
        self.assertEqual(self.m.uids_matching_endpoints('127.0.0', skip_loopback=True), set())
        self.assertEqual(self.m.uids_matching_endpoints('93.184', skip_loopback=True), {uid11})

    def test_dns_names(self):
        self.m.on_dns(500, 'GitHub.com.', 'type:  5 x.net;::ffff:140.82.121.4;', 0)
        traffic(self.m, 500, '140.82.121.4', 443, 50000, sent=1)
        traffic(self.m, 501, '140.82.121.4', 443, 50001, sent=1)
        traffic(self.m, 502, '151.101.1.1', 443, 50002, sent=1)
        self.m.process_pending()
        ep = proc_by_pid(self.m, 500).endpoints[('TCP', '140.82.121.4', 443, False)]
        self.assertEqual((ep.host, ep.host_q), ('github.com', 2))
        other = proc_by_pid(self.m, 501).endpoints[('TCP', '140.82.121.4', 443, False)]
        self.assertEqual((other.host, other.host_q), ('github.com', 1))
        late = proc_by_pid(self.m, 502).endpoints[('TCP', '151.101.1.1', 443, False)]
        self.assertEqual(late.host, '')
        self.m.on_dns(502, 'pypi.org', '151.101.1.1;', 0)   # имя стало известно позже
        self.m.process_pending()
        self.assertEqual((late.host, late.host_q), ('pypi.org', 2))

    def test_rdns_requests(self):
        self.m.resolve_names = True
        traffic(self.m, 600, '8.8.4.4', 443, 50000, sent=1)
        traffic(self.m, 600, '127.0.0.1', 1, 50001, sent=1, local='127.0.0.1')
        self.m.process_pending()
        self.assertEqual(self.m.take_rdns_wanted(), ['8.8.4.4'])
        self.assertEqual(self.m.take_rdns_wanted(), [])
        self.m.on_rdns('8.8.4.4', 'dns.google')
        ep = proc_by_pid(self.m, 600).endpoints[('TCP', '8.8.4.4', 443, False)]
        self.assertEqual((ep.host, ep.host_q), ('dns.google', 0))


class LifecycleTest(unittest.TestCase):
    def setUp(self):
        self.m = Model()
        self.m.resolve_names = False
        self.m.nt_path = lambda p: p.replace('\\Device\\HarddiskVolume3', 'C:')

    def test_start_traffic_stop(self):
        self.m.on_process_start(900, 10.0, '\\Device\\HarddiskVolume3\\Windows\\curl.exe')
        traffic(self.m, 900, '93.184.215.14', 443, 50000, recv=5000, ts=10.5)
        self.m.on_process_stop(900, 11.0)
        traffic(self.m, 900, '93.184.215.14', 443, 50000, recv=100, ts=10.9)  # запоздавшее событие
        self.m.process_pending()
        p = proc_by_pid(self.m, 900)
        self.assertEqual((p.name, p.path), ('curl.exe', 'C:\\Windows\\curl.exe'))
        self.assertEqual((p.recv, p.started, p.ended), (5100, 10.0, 11.0))

    def test_pid_reuse_creates_new_record(self):
        self.m.on_process_start(1000, 10.0, 'C:\\a.exe')
        traffic(self.m, 1000, '1.1.1.1', 443, 50000, sent=1, ts=11)
        self.m.on_process_stop(1000, 12.0)
        self.m.on_process_start(1000, 20.0, 'C:\\b.exe')
        traffic(self.m, 1000, '1.1.1.1', 443, 50000, sent=2, ts=21)
        self.m.process_pending()
        names = sorted((p.name, p.sent, p.ended is None) for p in self.m.procs.values())
        self.assertEqual(names, [('a.exe', 1, False), ('b.exe', 2, True)])

    def test_snapshot_then_late_start_event_is_same_process(self):
        self.m.sync_processes({1100: ('app.exe', 1)}, now=50.0)
        self.m.on_process_start(1100, 49.5, 'C:\\app.exe')   # событие пришло позже снимка
        self.m.process_pending()
        self.assertEqual(len(self.m.procs), 1)
        self.assertEqual(proc_by_pid(self.m, 1100).path, 'C:\\app.exe')

    def test_snapshot_ends_and_detects_reuse(self):
        self.m.sync_processes({1: ('a.exe', 0), 2: ('b.exe', 0)}, now=1.0)
        self.m.sync_processes({1: ('a.exe', 0)}, now=2.0)
        old_b = [p for p in self.m.procs.values() if p.pid == 2][0]
        self.assertEqual(old_b.ended, 2.0)
        self.m.sync_processes({1: ('a.exe', 0), 2: ('b.exe', 0)}, now=3.0)   # PID снова занят
        self.m.sync_processes({1: ('c.exe', 0), 2: ('b.exe', 0)}, now=4.0)   # другое имя
        self.assertEqual(len(self.m.procs), 4)
        self.assertEqual(proc_by_pid(self.m, 1).name, 'c.exe')

    def test_zombie_does_not_duplicate(self):
        self.m.sync_processes({5: ('z.exe', 0)}, now=1.0)
        self.m.on_process_stop(5, 1.5)
        self.m.process_pending()
        self.m.sync_processes({5: ('z.exe', 0)}, now=2.0)   # процесс ещё виден в снимке
        self.assertEqual(len(self.m.procs), 1)

    def test_special_pids(self):
        self.m.sync_processes({0: ('[System Process]', 0), 4: ('System', 0)}, now=1.0)
        self.m.sync_processes({0: ('[System Process]', 0), 4: ('System', 0)}, now=2.0)
        self.assertEqual(len(self.m.procs), 2)
        self.assertEqual(proc_by_pid(self.m, 0).name, 'Ядро (PID 0)')

    def test_details_and_tcp_table(self):
        self.m.sync_processes({77: ('svc.exe', 1)}, now=1.0)
        self.assertEqual(self.m.pending_details(), [(1, 77)])
        self.m.fill_details(1, {'path': 'C:\\S\\svc.exe', 'started': 0.5, 'cmdline': 'svc -x'})
        self.assertEqual(self.m.pending_details(), [])
        rows = [(77, 5, LOCAL, 50000, '1.2.3.4', 443), (77, 5, LOCAL, 50001, '1.2.3.4', 443),
                (77, 11, LOCAL, 50002, '5.5.5.5', 80), (0, 11, LOCAL, 50003, '6.6.6.6', 80)]
        self.m.sync_tcp(rows, 3.0)
        p = proc_by_pid(self.m, 77)
        ep = p.endpoints[('TCP', '1.2.3.4', 443, False)]
        self.assertEqual((ep.state, ep.conns, p.conns), ('ESTABLISHED', 2, 3))
        self.assertNotIn(0, self.m.by_pid)          # TIME_WAIT без владельца пропускаем
        self.m.sync_tcp([], 4.0)
        self.assertEqual((ep.state, ep.conns), ('', 0))

    def test_details_of_new_pid_owner_do_not_touch_old_record(self):
        # отчёт, п. 3: old.exe (PID 100) завершился, PID достался new.exe
        self.m.on_process_start(100, 1.0, 'C:\\old.exe')
        traffic(self.m, 100, '1.1.1.1', 443, 50000, sent=10, ts=2.0)
        self.m.on_process_stop(100, 3.0)
        self.m.process_pending()
        old = proc_by_pid(self.m, 100)
        self.assertEqual(self.m.pending_details(), [])      # завершённым подробности не нужны
        self.m.fill_details(old.uid, {'path': 'C:\\new.exe', 'started': 4.0}, now=5.0)
        self.assertEqual((old.name, old.path, old.started, old.ended, old.sent),
                         ('old.exe', 'C:\\old.exe', 1.0, 3.0, 10))

    def test_details_from_reused_pid_start_a_new_record(self):
        # запись создана по снимку; до чтения подробностей PID успел смениться
        self.m.sync_processes({7: ('app.exe', 1)}, now=100.0)
        (uid, pid), = self.m.pending_details()
        traffic(self.m, 7, '1.1.1.1', 443, 50000, sent=10, ts=101.0)
        self.m.process_pending()
        self.m.fill_details(uid, {'path': 'C:\\other.exe', 'started': 150.0}, now=151.0)
        old = self.m.procs[uid]
        new = proc_by_pid(self.m, 7)
        self.assertIsNot(old, new)
        self.assertEqual((old.name, old.path, old.sent), ('app.exe', '', 10))
        self.assertTrue(old.ended >= 101.0)
        self.assertEqual((new.name, new.started, new.ended, new.sent), ('other.exe', 150.0, None, 0))

    def test_details_name_mismatch_without_start_time(self):
        self.m.sync_processes({7: ('app.exe', 1)}, now=100.0)
        (uid, pid), = self.m.pending_details()
        self.m.fill_details(uid, {'path': '\\Device\\HarddiskVolume3\\b.exe'}, now=101.0)
        self.assertEqual(self.m.procs[uid].name, 'app.exe')
        self.assertEqual(proc_by_pid(self.m, 7).name, 'b.exe')

    def test_accept_ports_belong_to_instance(self):
        # отчёт, п. 5: новый процесс с тем же PID не наследует «входящие» прежнего
        self.m.on_process_start(100, 1.0, 'C:\\old.exe')
        self.m.on_accept(100, port(50000), 1.5)
        self.m.on_process_stop(100, 2.0)
        self.m.on_process_start(100, 5.0, 'C:\\new.exe')
        traffic(self.m, 100, '8.8.8.8', 443, 50000, sent=10, ts=6.0)
        self.m.process_pending()
        self.assertEqual(list(proc_by_pid(self.m, 100).endpoints), [('TCP', '8.8.8.8', 443, False)])

    def test_connections_reset_when_process_ends(self):
        self.m.sync_processes({7: ('a.exe', 1)}, now=1.0)
        self.m.sync_tcp([(7, 5, LOCAL, 50000, '1.2.3.4', 443)], 1.0)
        self.m.on_process_stop(7, 2.0)
        self.m.on_process_start(7, 3.0, 'C:\\b.exe')
        self.m.process_pending()
        self.m.sync_processes({7: ('b.exe', 1)}, now=4.0)
        self.m.sync_tcp([], 4.0)
        self.assertEqual(sorted((p.name, p.conns) for p in self.m.procs.values()),
                         [('a.exe', 0), ('b.exe', 0)])

    def test_late_packet_goes_to_previous_instance(self):
        self.m.on_process_start(100, 1.0, 'C:\\old.exe')
        self.m.on_process_stop(100, 3.0)
        self.m.on_process_start(100, 10.0, 'C:\\new.exe')
        traffic(self.m, 100, '1.1.1.1', 443, 50000, sent=7, ts=2.5)    # пришёл с опозданием
        traffic(self.m, 100, '2.2.2.2', 443, 50001, sent=9, ts=11.0)
        self.m.process_pending()
        by_name = {p.name: p for p in self.m.procs.values()}
        self.assertEqual((by_name['old.exe'].sent, by_name['new.exe'].sent), (7, 9))

    def test_traffic_after_exit_belongs_to_new_owner(self):
        self.m.on_process_start(100, 1.0, 'C:\\old.exe')
        self.m.on_process_stop(100, 3.0)
        traffic(self.m, 100, '2.2.2.2', 443, 50001, sent=9, ts=8.0)    # запуск ещё не дошёл
        self.m.on_process_start(100, 7.9, 'C:\\new.exe')
        self.m.process_pending()
        by_name = {p.name: p for p in self.m.procs.values()}
        self.assertEqual(sorted(by_name), ['new.exe', 'old.exe'])
        self.assertEqual((by_name['old.exe'].sent, by_name['new.exe'].sent), (0, 9))
        self.assertEqual(by_name['new.exe'].started, 7.9)

    def test_stop_event_after_next_start(self):
        self.m.on_process_start(100, 1.0, 'C:\\old.exe')
        self.m.on_process_start(100, 10.0, 'C:\\new.exe')
        self.m.on_process_stop(100, 9.5)     # события из разных буферов пришли не по порядку
        self.m.process_pending()
        by_name = {p.name: p for p in self.m.procs.values()}
        self.assertEqual((by_name['old.exe'].ended, by_name['new.exe'].ended), (9.5, None))

    def test_late_stop_does_not_end_newer_instance_without_start_time(self):
        self.m.on_process_start(100, 1.0, 'C:\\old.exe')
        self.m.process_pending()
        self.m.sync_processes({100: ('new.exe', 1)}, now=12.0)   # PID уже у нового процесса
        self.m.on_process_stop(100, 10.0)                       # запоздавшая остановка old.exe
        self.m.process_pending()
        by_name = {p.name: p for p in self.m.procs.values()}
        self.assertEqual((by_name['old.exe'].ended, by_name['new.exe'].ended), (10.0, None))

    def test_empty_snapshot_is_ignored(self):
        self.m.sync_processes({7: ('a.exe', 1)}, now=1.0)
        self.m.sync_processes({}, now=2.0)
        self.assertIsNone(proc_by_pid(self.m, 7).ended)

    def test_dead_pid_in_tcp_table_is_not_a_new_process(self):
        self.m.sync_processes({7: ('a.exe', 1), 8: ('b.exe', 1)}, now=1.0)
        self.m.sync_processes({8: ('b.exe', 1)}, now=2.0)
        self.m.sync_tcp([(7, 8, LOCAL, 50000, '1.2.3.4', 443)], 2.0)     # CLOSE_WAIT мертвеца
        self.assertEqual(len([p for p in self.m.procs.values() if p.pid == 7]), 1)

    def _fast_reuse(self, gap, new_name):
        # снимок увидел old.exe; через gap секунд PID уже у другого процесса, а подробности
        # читаются только после этого (отчёт 1.1, R3)
        self.m.sync_processes({100: ('old.exe', 1)}, now=100.0)
        uid = proc_by_pid(self.m, 100).uid
        traffic(self.m, 100, '1.1.1.1', 443, 50000, sent=10, ts=100.1)
        self.m.process_pending()
        self.m.fill_details(uid, {'path': 'C:\\%s' % new_name, 'started': 100.0 + gap},
                            now=100.0 + gap + 0.1)
        return self.m.procs[uid], proc_by_pid(self.m, 100)

    def test_fast_pid_reuse_by_other_exe(self):
        for gap in (0.1, 0.5, 1.9):
            self.m = Model()
            self.m.resolve_names = False
            old, new = self._fast_reuse(gap, 'new.exe')
            self.assertIsNot(old, new, gap)
            self.assertEqual((old.name, old.sent), ('old.exe', 10), gap)
            self.assertEqual((new.name, new.started, new.sent), ('new.exe', 100.0 + gap, 0), gap)

    def test_fast_pid_reuse_by_same_exe(self):
        # имя то же — различаем по времени: процесс создан позже, чем мы видели PID живым
        for gap in (0.1, 0.5, 1.9):
            self.m = Model()
            self.m.resolve_names = False
            old, new = self._fast_reuse(gap, 'old.exe')
            self.assertIsNot(old, new, gap)
            self.assertEqual((old.sent, new.sent), (10, 0), gap)

    def test_details_of_the_same_process_are_accepted(self):
        self.m.sync_processes({100: ('app.exe', 1)}, now=100.0)
        uid = proc_by_pid(self.m, 100).uid
        self.m.fill_details(uid, {'path': 'C:\\App.EXE', 'started': 99.99}, now=100.2)
        self.assertEqual(len(self.m.procs), 1)
        self.assertEqual((proc_by_pid(self.m, 100).path, proc_by_pid(self.m, 100).started),
                         ('C:\\App.EXE', 99.99))
        self.m.on_process_start(200, 50.0, 'C:\\b.exe')
        self.m.process_pending()
        b = proc_by_pid(self.m, 200)
        self.m.fill_details(b.uid, {'path': 'C:\\b.exe', 'started': 50.01}, now=60.0)
        self.assertIs(proc_by_pid(self.m, 200), b)

    def test_late_packet_with_same_addresses(self):
        # отчёт 1.1, R4: одинаковые адреса и порты у старого и нового процесса с одним PID
        for order in ([(2.5, 7), (11.0, 9)], [(11.0, 9), (2.5, 7)]):
            self.m = Model()
            self.m.resolve_names = False
            self.m.on_process_start(100, 1.0, 'C:\\old.exe')
            self.m.on_process_stop(100, 3.0)
            self.m.on_process_start(100, 10.0, 'C:\\new.exe')
            for ts, size in order:
                traffic(self.m, 100, '1.1.1.1', 443, 50000, sent=size, ts=ts)
            self.m.process_pending()
            self.assertEqual({p.name: p.sent for p in self.m.procs.values()},
                             {'old.exe': 7, 'new.exe': 9}, order)

    def _fresh(self):
        self.m = Model()
        self.m.resolve_names = False
        return self.m

    def test_same_exe_name_in_other_directory(self):
        # отчёт 1.2, V12-1: C:\Old\app.exe и C:\Other\app.exe — разные программы
        # (и когда время создания известно, и когда его прочитать не удалось)
        for started in (100.4, None):
            m = self._fresh()
            m.on_process_start(100, 100.0, 'C:\\Old\\app.exe')
            traffic(m, 100, '1.1.1.1', 443, 50000, sent=10, ts=100.1)
            m.process_pending()
            old = proc_by_pid(m, 100)
            m.fill_details(old.uid, {'path': 'C:\\Other\\app.exe', 'started': started}, now=100.5)
            new = proc_by_pid(m, 100)
            self.assertIsNot(old, new, started)
            self.assertEqual((old.path, old.started, old.sent), ('C:\\Old\\app.exe', 100.0, 10),
                             started)
            self.assertEqual((new.path, new.started, new.sent), ('C:\\Other\\app.exe', started, 0),
                             started)

    def test_same_full_path_started_right_after(self):
        # отчёт 1.2, V12-1: тот же exe по тому же пути запущен почти сразу после прежнего;
        # различаем по времени создания, а не по каталогу
        for gap in (0.1, 0.4):
            m = self._fresh()
            m.on_process_start(100, 100.0, 'C:\\App\\app.exe')
            traffic(m, 100, '1.1.1.1', 443, 50000, sent=10, ts=100.05)
            m.process_pending()
            old = proc_by_pid(m, 100)
            m.fill_details(old.uid, {'path': 'C:\\App\\app.exe', 'started': 100.0 + gap},
                           now=100.0 + gap + 0.1)
            new = proc_by_pid(m, 100)
            self.assertIsNot(old, new, gap)
            self.assertEqual((old.started, old.sent), (100.0, 10), gap)
            self.assertEqual((new.path, new.started, new.sent),
                             ('C:\\App\\app.exe', 100.0 + gap, 0), gap)

    def test_second_start_of_same_exe_without_stop_event(self):
        # запуск того же exe с тем же PID, а остановка прежнего дошла последней
        self.m.on_process_start(100, 100.0, 'C:\\App\\app.exe')
        traffic(self.m, 100, '1.1.1.1', 443, 50000, sent=10, ts=100.05)
        self.m.on_process_start(100, 100.1, 'C:\\App\\app.exe')
        traffic(self.m, 100, '1.1.1.1', 443, 50000, sent=9, ts=100.2)
        self.m.on_process_stop(100, 100.08)
        self.m.process_pending()
        old, new = sorted(self.m.procs.values(), key=lambda p: p.started)
        self.assertEqual((old.started, old.ended, old.sent), (100.0, 100.08, 10))
        self.assertEqual((new.started, new.ended, new.sent), (100.1, None, 9))

    def test_path_forms_that_cannot_be_compared_fall_back_to_name(self):
        # сетевой путь и путь \Device\… разные функции Windows пишут по-разному: тут
        # сравниваются имена файлов, а экземпляры различает время создания
        for etw_path, info_path in (('\\\\srv\\share\\app.exe', 'Z:\\app.exe'),
                                    ('\\Device\\HarddiskVolume9\\App\\app.exe', 'C:\\App\\app.exe')):
            m = self._fresh()
            m.on_process_start(100, 100.0, etw_path)
            m.process_pending()
            proc = proc_by_pid(m, 100)
            m.fill_details(proc.uid, {'path': info_path, 'started': 99.99}, now=100.5)
            self.assertIs(proc_by_pid(m, 100), proc, etw_path)
            self.assertEqual((len(m.procs), proc.path), (1, info_path), etw_path)

    def test_delayed_packet_near_close_lifetimes(self):
        # отчёт 1.2, V12-2: old.exe 1.0–3.0, new.exe с тем же PID с 3.1; пакет в 2.9 точно
        # попадает во время жизни old.exe и не должен уйти в допуск new.exe
        for order in ([(2.9, 7), (3.2, 9)], [(3.2, 9), (2.9, 7)]):
            m = self._fresh()
            m.on_process_start(100, 1.0, 'C:\\old.exe')
            m.on_process_stop(100, 3.0)
            m.on_process_start(100, 3.1, 'C:\\new.exe')
            for ts, size in order:
                traffic(m, 100, '1.1.1.1', 443, 50000, sent=size, ts=ts)
            m.process_pending()
            self.assertEqual({p.name: p.sent for p in m.procs.values()},
                             {'old.exe': 7, 'new.exe': 9}, order)

    def test_packets_near_stop_and_start(self):
        # остановка old.exe в 3.0, запуск new.exe в 3.1; пакет между ними — ещё old.exe:
        # new.exe тогда не существовал. Пакет у границы и пакеты из середины жизни обоих
        # процессов (с теми же адресами) приходят в обоих порядках
        for ts, owner in ((2.99, 'old.exe'), (3.0, 'old.exe'), (3.04, 'old.exe'),
                          (3.1, 'new.exe'), (3.11, 'new.exe')):
            for edge_first in (True, False):
                m = self._fresh()
                m.on_process_start(100, 1.0, 'C:\\old.exe')
                m.on_process_stop(100, 3.0)
                m.on_process_start(100, 3.1, 'C:\\new.exe')
                packets = [(2.0, 100), (5.0, 1000)]
                packets.insert(0 if edge_first else 2, (ts, 1))
                for when, size in packets:
                    traffic(m, 100, '1.1.1.1', 443, 50000, sent=size, ts=when)
                m.process_pending()
                expected = {'old.exe': 100, 'new.exe': 1000}
                expected[owner] += 1
                self.assertEqual({p.name: p.sent for p in m.procs.values()}, expected,
                                 (ts, edge_first))

    def test_data_sent_right_after_exit_stays_with_process(self):
        # ядро ещё недолго досылает данные завершённого процесса от его имени
        self.m.on_process_start(100, 1.0, 'C:\\old.exe')
        self.m.on_process_stop(100, 3.0)
        traffic(self.m, 100, '1.1.1.1', 443, 50000, sent=5, ts=3.2)
        self.m.process_pending()
        self.assertEqual([(p.name, p.sent) for p in self.m.procs.values()], [('old.exe', 5)])

    def test_newer_instance_without_start_time_does_not_take_old_packet(self):
        self.m.on_process_start(100, 1.0, 'C:\\old.exe')
        self.m.on_process_stop(100, 3.0)
        self.m.process_pending()
        self.m.sync_processes({100: ('new.exe', 1)}, now=5.0)   # время запуска пока неизвестно
        traffic(self.m, 100, '1.1.1.1', 443, 50000, sent=7, ts=2.9)    # запоздавший пакет old.exe
        traffic(self.m, 100, '1.1.1.1', 443, 50000, sent=9, ts=5.5)
        self.m.process_pending()
        self.assertEqual({p.name: p.sent for p in self.m.procs.values()},
                         {'old.exe': 7, 'new.exe': 9})

    def test_start_time_limits_previous_owner_end(self):
        # прежний владелец PID пропал из снимка в 10.0, а новый запущен в 9.0:
        # значит, прежний завершился не позже 9.0
        self.m.sync_processes({100: ('old.exe', 1)}, now=5.0)
        self.m.sync_processes({1: ('other.exe', 0)}, now=10.0)
        old = proc_by_pid(self.m, 100)
        self.assertEqual(old.ended, 10.0)
        self.m.on_process_start(100, 9.0, 'C:\\new.exe')
        traffic(self.m, 100, '1.1.1.1', 443, 50000, sent=9, ts=9.5)
        self.m.process_pending()
        new = proc_by_pid(self.m, 100)
        self.assertEqual((old.ended, old.sent, new.started, new.sent), (9.0, 0, 9.0, 9))

    def test_start_right_after_explicit_stop(self):
        # отчёт 1.3, V13-1: остановка, а через доли секунды (меньше CLOCK_EPS) — запуск
        # с тем же PID, другого или того же exe; трафик после запуска — уже нового процесса
        for new_path in ('C:\\new.exe', 'C:\\old.exe'):
            m = self._fresh()
            m.on_process_start(100, 100.0, 'C:\\old.exe')
            traffic(m, 100, '1.1.1.1', 443, 50000, sent=10, ts=100.005)
            m.on_process_stop(100, 100.01)
            m.on_process_start(100, 100.02, new_path)
            traffic(m, 100, '1.1.1.1', 443, 50000, sent=9, ts=100.03)
            m.process_pending()
            old, new = sorted(m.procs.values(), key=lambda p: p.uid)
            self.assertEqual((old.started, old.ended, old.sent), (100.0, 100.01, 10), new_path)
            self.assertEqual((new.path, new.started, new.ended, new.sent),
                             (new_path, 100.02, None, 9), new_path)
            self.assertIs(proc_by_pid(m, 100), new, new_path)

    def test_start_right_after_stop_of_record_from_traffic(self):
        # о запуске прежнего процесса не знали (запись по трафику), но остановка дошла
        traffic(self.m, 100, '1.1.1.1', 443, 50000, sent=10, ts=100.0)
        self.m.on_process_stop(100, 100.01)
        self.m.on_process_start(100, 100.02, 'C:\\new.exe')
        traffic(self.m, 100, '1.1.1.1', 443, 50000, sent=9, ts=100.03)
        self.m.process_pending()
        old, new = sorted(self.m.procs.values(), key=lambda p: p.uid)
        self.assertEqual((old.ended, old.sent), (100.01, 10))
        self.assertEqual((new.name, new.started, new.ended, new.sent), ('new.exe', 100.02, None, 9))

    def test_start_right_after_traffic_of_previous_owner(self):
        # пакет в 100.0 — процесс уже жил; запуск в 100.02 (меньше CLOCK_EPS) не может быть
        # его собственным: PID уже у нового процесса, а остановка прежнего дошла последней
        traffic(self.m, 100, '1.1.1.1', 443, 50000, sent=10, ts=100.0)
        self.m.on_process_start(100, 100.02, 'C:\\new.exe')
        traffic(self.m, 100, '1.1.1.1', 443, 50000, sent=9, ts=100.03)
        self.m.on_process_stop(100, 100.01)
        self.m.process_pending()
        old, new = sorted(self.m.procs.values(), key=lambda p: p.uid)
        self.assertEqual((old.ended, old.sent), (100.01, 10))
        self.assertEqual((new.name, new.started, new.ended, new.sent), ('new.exe', 100.02, None, 9))

    def test_late_start_of_record_from_traffic_is_merged(self):
        # запуск дошёл позже пакетов и даже позже остановки — лишней записи нет
        traffic(self.m, 100, '1.1.1.1', 443, 50000, sent=10, ts=5.0)
        self.m.on_process_stop(100, 5.5)
        self.m.on_process_start(100, 4.9, 'C:\\app.exe')
        self.m.process_pending()
        (p,) = self.m.procs.values()
        self.assertEqual((p.name, p.started, p.ended, p.sent), ('app.exe', 4.9, 5.5, 10))

    def test_late_start_of_older_instance_is_merged_into_it(self):
        # запуск прежнего владельца PID дошёл уже после запуска нового
        traffic(self.m, 100, '1.1.1.1', 443, 50000, sent=10, ts=1.0)
        self.m.on_process_stop(100, 3.0)
        self.m.on_process_start(100, 3.1, 'C:\\new.exe')
        self.m.on_process_start(100, 0.9, 'C:\\old.exe')
        self.m.process_pending()
        self.assertEqual(sorted((p.name, p.started, p.ended, p.sent) for p in self.m.procs.values()),
                         [('new.exe', 3.1, None, 0), ('old.exe', 0.9, 3.0, 10)])

    def test_start_is_checked_against_known_creation_time(self):
        # запись по снимку в 10.0; GetProcessTimes уже сообщил время создания.
        # Запуск в 10.02 — свой, только если время создания с ним сходится
        for created, same in ((9.6, True), (5.0, False)):
            m = self._fresh()
            m.sync_processes({100: ('app.exe', 1)}, now=10.0)
            uid = proc_by_pid(m, 100).uid
            m.fill_details(uid, {'path': 'C:\\app.exe', 'started': created}, now=10.0)
            m.on_process_start(100, 9.61 if same else 10.02, 'C:\\app.exe')
            traffic(m, 100, '1.1.1.1', 443, 50000, sent=9, ts=10.03)
            m.process_pending()
            procs = sorted(m.procs.values(), key=lambda p: p.uid)
            if same:
                self.assertEqual([(p.started, p.ended, p.sent) for p in procs],
                                 [(9.6, None, 9)])
            else:
                self.assertEqual([(p.started, p.ended, p.sent) for p in procs],
                                 [(5.0, 10.02, 0), (10.02, None, 9)])

    def test_stale_start_of_previous_owner_does_not_confirm_current(self):
        # отчёт 1.4, V14-1: запись текущего процесса создана снимком, путь и время создания
        # известны. Запоздавший запуск прежнего владельца PID (другой exe или тот же) не делает
        # её «уже запущенной», и настоящий запуск не создаёт дубликат
        path = 'C:\\New\\app.exe'
        for old_path in ('C:\\Old\\app.exe', path):
            m = self._fresh()
            m.sync_processes({100: ('app.exe', 1)}, now=10.02)
            m.fill_details(proc_by_pid(m, 100).uid, {'path': path, 'started': 10.01}, now=10.02)
            traffic(m, 100, '1.1.1.1', 443, 50000, sent=10, ts=10.025)
            m.process_pending()
            m.on_process_start(100, 10.0, old_path)
            m.on_process_start(100, 10.015, path)
            traffic(m, 100, '1.1.1.1', 443, 50000, sent=9, ts=10.03)
            m.process_pending()
            current = proc_by_pid(m, 100)
            self.assertEqual((current.path, current.started, current.ended, current.sent),
                             (path, 10.01, None, 19), old_path)
            # прежний владелец PID получил свою запись (без сети) и завершился до текущего
            others = [(p.path, p.started, p.ended, p.sent) for p in m.procs.values()
                      if p is not current]
            self.assertEqual(others, [(old_path, 10.0, 10.01, 0)], old_path)

    def test_latest_matching_start_wins(self):
        # запись создана пакетом (в прошлой пачке событий); потом дошли два запоздавших
        # запуска: прежнего владельца PID и самого процесса. Своим считается более поздний,
        # путь и время берутся из него
        traffic(self.m, 100, '1.1.1.1', 443, 50000, sent=10, ts=10.025)
        self.m.process_pending()
        self.m.on_process_start(100, 10.0, 'C:\\Old\\app.exe')
        self.m.on_process_start(100, 10.015, 'C:\\New\\app.exe')
        traffic(self.m, 100, '1.1.1.1', 443, 50000, sent=9, ts=10.03)
        self.m.process_pending()
        p = proc_by_pid(self.m, 100)
        self.assertEqual((p.path, p.name, p.started, p.ended, p.sent),
                         ('C:\\New\\app.exe', 'app.exe', 10.015, None, 19))
        # вытесненный запуск — прежнего владельца PID: у него отдельная запись без сети
        self.assertEqual(sorted((q.path, q.started, q.ended, q.sent) for q in self.m.procs.values()),
                         [('C:\\New\\app.exe', 10.015, None, 19),
                          ('C:\\Old\\app.exe', 10.0, 10.015, 0)])
        self.m.on_process_start(100, 10.005, 'C:\\Older\\app.exe')     # ещё более ранний — не его
        self.m.process_pending()
        self.assertEqual((p.path, p.started, p.sent), ('C:\\New\\app.exe', 10.015, 19))
        self.assertEqual(sorted((q.path, q.started, q.ended, q.sent) for q in self.m.procs.values()),
                         [('C:\\New\\app.exe', 10.015, None, 19),
                          ('C:\\Old\\app.exe', 10.0, 10.005, 0),
                          ('C:\\Older\\app.exe', 10.005, 10.015, 0)])

    def test_events_of_one_batch_are_applied_in_time_order(self):
        # те же события, но все в одной пачке: по времени это запуск Old.exe, запуск New.exe
        # и пакеты. Значит, Old.exe — прежний владелец PID (без сети), пакеты — New.exe
        traffic(self.m, 100, '1.1.1.1', 443, 50000, sent=10, ts=10.025)
        self.m.on_process_start(100, 10.0, 'C:\\Old\\app.exe')
        self.m.on_process_start(100, 10.015, 'C:\\New\\app.exe')
        traffic(self.m, 100, '1.1.1.1', 443, 50000, sent=9, ts=10.03)
        self.m.process_pending()
        self.assertEqual(sorted((p.path, p.started, p.ended, p.sent) for p in self.m.procs.values()),
                         [('C:\\New\\app.exe', 10.015, None, 19),
                          ('C:\\Old\\app.exe', 10.0, 10.015, 0)])

    def test_earlier_of_two_matching_starts_is_previous_owner(self):
        # запись из снимка (10.0) приняла запуск в 10.04; запуск в 10.02 дошёл позже (или в той
        # же пачке). Запусков два — значит, и процессов два: запись остаётся работающей
        # с запуском 10.04, а запуск 10.02 — прежнего владельца PID (своя запись без сети)
        for separate in (True, False):
            m = self._fresh()
            m.sync_processes({100: ('app.exe', 1)}, now=10.0)
            current = proc_by_pid(m, 100)
            m.on_process_start(100, 10.04, 'C:\\app.exe')
            if separate:
                m.process_pending()
            m.on_process_start(100, 10.02, 'C:\\app.exe')
            m.process_pending()
            self.assertIs(proc_by_pid(m, 100), current, separate)
            self.assertEqual(sorted((p.started, p.ended, p.path) for p in m.procs.values()),
                             [(10.02, 10.04, 'C:\\app.exe'), (10.04, None, 'C:\\app.exe')],
                             separate)

    def test_path_taken_from_late_start_is_corrected_by_details(self):
        # путь из запоздавшего запуска взят на веру (он мог быть от прежнего владельца PID);
        # точные сведения от Windows его исправляют, а не считаются чужими
        traffic(self.m, 100, '1.1.1.1', 443, 50000, sent=10, ts=10.025)
        self.m.process_pending()
        self.m.on_process_start(100, 10.0, 'C:\\Old\\app.exe')
        self.m.process_pending()
        (p,) = self.m.procs.values()
        self.assertEqual((p.path, p.started), ('C:\\Old\\app.exe', 10.0))
        self.m.fill_details(p.uid, {'path': 'C:\\New\\app.exe', 'started': 10.012}, now=10.5)
        self.assertEqual([(q.path, q.started, q.sent) for q in self.m.procs.values()],
                         [('C:\\New\\app.exe', 10.012, 10)])

    def test_traffic_moves_to_owner_revealed_by_details(self):
        # запуск Old.exe и пакет пришли в одной пачке: пакет сначала достался Old.exe.
        # Windows сообщает, что PID сейчас у New.exe, созданного в 10.012, — раньше пакета.
        # Адресат, впервые замеченный уже при New.exe, переходит к нему
        traffic(self.m, 100, '1.1.1.1', 443, 50000, sent=10, ts=10.025)
        self.m.on_process_start(100, 10.0, 'C:\\Old\\app.exe')
        self.m.process_pending()
        old = proc_by_pid(self.m, 100)
        self.m.fill_details(old.uid, {'path': 'C:\\New\\app.exe', 'started': 10.012}, now=10.5)
        self.assertEqual(sorted((p.path, p.started, p.ended, p.sent) for p in self.m.procs.values()),
                         [('C:\\New\\app.exe', 10.012, None, 10),
                          ('C:\\Old\\app.exe', 10.0, 10.012, 0)])

    def test_record_from_snapshot_does_not_absorb_next_start(self):
        # отчёт 1.4, V14-3: запись из снимка, от процесса уже был пакет. Следующий запуск
        # с тем же PID — новый процесс (другой exe или тот же), хотя остановка прежнего
        # дошла позже запуска. С подробностями от Windows и без них
        for new_path in ('C:\\new.exe', 'C:\\old.exe'):
            for details in (True, False):
                m = self._fresh()
                m.sync_processes({100: ('old.exe', 1)}, now=100.0)
                if details:
                    m.fill_details(proc_by_pid(m, 100).uid,
                                   {'path': 'C:\\old.exe', 'started': 99.6}, now=100.0)
                traffic(m, 100, '1.1.1.1', 443, 50000, sent=10, ts=100.0)
                m.on_process_start(100, 100.02, new_path)
                traffic(m, 100, '1.1.1.1', 443, 50000, sent=9, ts=100.03)
                m.on_process_stop(100, 100.01)
                m.process_pending()
                old, new = sorted(m.procs.values(), key=lambda p: p.uid)
                self.assertEqual((old.name, old.ended, old.sent), ('old.exe', 100.01, 10),
                                 (new_path, details))
                self.assertEqual((new.path, new.started, new.ended, new.sent),
                                 (new_path, 100.02, None, 9), (new_path, details))
                self.assertIs(proc_by_pid(m, 100), new)

    def test_start_long_after_creation_time_is_another_process(self):
        # как V14-3, но пакета от прежнего процесса не было и exe тот же: различает время
        # создания (99.6) — событие о запуске пишется сразу при создании, а не через 0,4 с
        m = self.m
        m.sync_processes({100: ('app.exe', 1)}, now=100.0)
        m.fill_details(proc_by_pid(m, 100).uid, {'path': 'C:\\app.exe', 'started': 99.6}, now=100.0)
        m.on_process_start(100, 100.02, 'C:\\app.exe')
        traffic(m, 100, '1.1.1.1', 443, 50000, sent=9, ts=100.03)
        m.on_process_stop(100, 100.01)
        m.process_pending()
        self.assertEqual([(p.started, p.ended, p.sent)
                          for p in sorted(m.procs.values(), key=lambda p: p.uid)],
                         [(99.6, 100.01, 0), (100.02, None, 9)])

    def test_late_start_goes_to_instance_before_known_stop(self):
        # отчёт 1.4, V14-4: прежний владелец PID известен по пакету и событию о завершении (3.0),
        # новый — только по пакету. Запоздавший запуск в 0.9 раньше завершения прежнего, значит,
        # он прежнего; время его завершения остаётся 3.0, новый экземпляр не затронут
        traffic(self.m, 100, '1.1.1.1', 443, 50000, sent=10, ts=1.0)
        self.m.on_process_stop(100, 3.0)
        traffic(self.m, 100, '1.1.1.1', 443, 50000, sent=9, ts=4.0)
        self.m.on_process_start(100, 0.9, 'C:\\old.exe')
        self.m.process_pending()
        old, new = sorted(self.m.procs.values(), key=lambda p: p.uid)
        self.assertEqual((old.path, old.started, old.ended, old.sent), ('C:\\old.exe', 0.9, 3.0, 10))
        self.assertEqual((new.path, new.started, new.ended, new.sent), ('', None, None, 9))
        self.assertIs(proc_by_pid(self.m, 100), new)

    def test_guessed_end_is_not_moved_before_seen_activity(self):
        # время завершения «по догадке» (процесс пропал из снимка в 10.0) уточняется запуском
        # следующего процесса, но не раньше момента, когда прежний ещё точно работал (пакет в 6.0)
        self.m.sync_processes({100: ('old.exe', 1)}, now=5.0)
        traffic(self.m, 100, '1.1.1.1', 443, 50000, sent=10, ts=6.0)
        self.m.process_pending()
        self.m.sync_processes({1: ('other.exe', 0)}, now=10.0)
        old = proc_by_pid(self.m, 100)
        self.assertEqual(old.ended, 10.0)
        self.m.on_process_start(100, 5.5, 'C:\\new.exe')
        self.m.process_pending()
        self.assertEqual((old.ended, proc_by_pid(self.m, 100).started), (6.0, 5.5))

    def test_late_stop_refines_previous_owner_not_new_one(self):
        # новый владелец PID найден снимком (подробностей ещё нет), прежний считается
        # завершённым «по догадке». Запоздавшее событие о завершении — прежнего
        self.m.on_process_start(100, 1.0, 'C:\\old.exe')
        self.m.process_pending()
        self.m.sync_processes({100: ('new.exe', 1)}, now=5.0)
        self.m.on_process_stop(100, 4.9)
        self.m.process_pending()
        by_name = {p.name: p for p in self.m.procs.values()}
        self.assertEqual((by_name['old.exe'].ended, by_name['new.exe'].ended), (4.9, None))

    def test_stop_before_first_packet_is_not_this_process(self):
        # процесс известен только по пакету в 4.0; событие о завершении в 3.9 — не его
        # (прежнего владельца PID, записи о котором нет)
        traffic(self.m, 100, '1.1.1.1', 443, 50000, sent=9, ts=4.0)
        self.m.on_process_stop(100, 3.9)
        traffic(self.m, 100, '1.1.1.1', 443, 50000, sent=1, ts=4.5)
        self.m.process_pending()
        self.assertEqual([(p.ended, p.sent) for p in self.m.procs.values()], [(None, 10)])

    def test_stop_event_delivered_before_start_and_packets(self):
        # у короткоживущего процесса событие о завершении иногда приходит раньше события
        # о запуске и пакетов: оно не теряется, а запись не остаётся «работающей»
        for first in ('packet', 'start'):
            m = self._fresh()
            m.on_process_stop(100, 5.3)
            if first == 'packet':
                traffic(m, 100, '1.1.1.1', 443, 50000, sent=10, ts=5.1)
                m.on_process_start(100, 5.0, 'C:\\curl.exe')
            else:
                m.on_process_start(100, 5.0, 'C:\\curl.exe')
                traffic(m, 100, '1.1.1.1', 443, 50000, sent=10, ts=5.1)
            m.process_pending()
            self.assertEqual([(p.name, p.started, p.ended, p.sent) for p in m.procs.values()],
                             [('curl.exe', 5.0, 5.3, 10)], first)
            traffic(m, 100, '1.1.1.1', 443, 50000, sent=9, ts=9.0)    # следующий владелец PID
            m.process_pending()
            self.assertEqual(sorted((p.ended, p.sent) for p in m.procs.values()
                                    if p.ended is None), [(None, 9)], first)
            self.assertEqual(len(m.procs), 2, first)

    def test_early_stop_is_not_applied_to_later_process(self):
        self.m.on_process_stop(100, 5.3)                 # процесс, о котором записи так и не будет
        self.m.on_process_start(100, 8.0, 'C:\\app.exe')
        self.m.process_pending()
        self.assertEqual([(p.started, p.ended) for p in self.m.procs.values()], [(8.0, None)])
        # и «завершение из будущего» (например, после перевода часов) к записи не применяется
        m = self._fresh()
        m.on_process_stop(100, 5000.0)
        m.on_process_start(100, 8.0, 'C:\\app.exe')
        m.process_pending()
        self.assertEqual([(p.started, p.ended) for p in m.procs.values()], [(8.0, None)])

    def test_process_ends_at_first_stop_after_its_start(self):
        # процесс запущен в 1.0; событий о завершении два — в 2.0 и в 3.0. В 2.0 PID ещё был
        # у него (или у того, кто занял PID после него), значит, он завершился не позже 2.0;
        # событие в 3.0 — от процесса, о котором записи нет. Порядок прихода не важен,
        # и в одной пачке, и в разных
        for stops in ((3.0, 2.0), (2.0, 3.0)):
            for separate in (False, True):
                m = self._fresh()
                m.on_process_start(100, 1.0, 'C:\\old.exe')
                for ts in stops:
                    m.on_process_stop(100, ts)
                    if separate:
                        m.process_pending()
                m.process_pending()
                self.assertEqual(proc_by_pid(m, 100).ended, 2.0, (stops, separate))

    def test_stop_events_are_shared_out_in_any_order(self):
        # отчёт 1.5, п. 1: p1 работал 10–11, p2 с тем же PID — 12–13. Событие о завершении p2
        # пришло раньше запуска p2 и завершения p1 (или раньше запуска p1). Каждый получает своё
        orders = (
            [('start', 10.0, 'C:\\p1.exe'), ('stop', 13.0), ('start', 12.0, 'C:\\p2.exe'), ('stop', 11.0)],
            [('stop', 13.0), ('start', 10.0, 'C:\\p1.exe'), ('stop', 11.0), ('start', 12.0, 'C:\\p2.exe')],
            [('stop', 13.0), ('stop', 11.0), ('start', 12.0, 'C:\\p2.exe'), ('start', 10.0, 'C:\\p1.exe')],
        )
        for order in orders:
            for separate in (False, True):
                m = self._fresh()
                for event in order:
                    if event[0] == 'start':
                        m.on_process_start(100, event[1], event[2])
                    else:
                        m.on_process_stop(100, event[1])
                    if separate:
                        m.process_pending()
                m.process_pending()
                self.assertEqual(sorted((p.name, p.started, p.ended) for p in m.procs.values()),
                                 [('p1.exe', 10.0, 11.0), ('p2.exe', 12.0, 13.0)], (order, separate))

    def test_traffic_before_lifecycle_events_in_one_batch(self):
        # отчёт 1.5, п. 3: пакеты старого (10.0) и нового (15.0) процесса пришли раньше
        # событий о завершении старого (11.0) и запуске нового (12.0) в той же пачке
        self.m.on_process_start(100, 1.0, 'C:\\old.exe')
        traffic(self.m, 100, '1.1.1.1', 443, 50000, sent=10, ts=10.0)
        traffic(self.m, 100, '2.2.2.2', 443, 50001, sent=25, ts=15.0)
        self.m.on_process_stop(100, 11.0)
        self.m.on_process_start(100, 12.0, 'C:\\new.exe')
        self.m.process_pending()
        self.assertEqual({p.name: p.sent for p in self.m.procs.values()},
                         {'old.exe': 10, 'new.exe': 25})

    def test_late_start_moves_traffic_of_same_address(self):
        # пакет нового процесса к тому же адресату, что и у прежнего, пришёл раньше событий
        # о смене владельца PID (в другой пачке): он переходит к новому
        self.m.on_process_start(100, 1.0, 'C:\\old.exe')
        traffic(self.m, 100, '1.1.1.1', 443, 50000, sent=10, ts=2.0)
        self.m.process_pending()
        traffic(self.m, 100, '1.1.1.1', 443, 50001, sent=25, ts=3.3)
        self.m.process_pending()
        self.m.on_process_stop(100, 3.0)
        self.m.on_process_start(100, 3.2, 'C:\\new.exe')
        self.m.process_pending()
        self.assertEqual({p.name: p.sent for p in self.m.procs.values()},
                         {'old.exe': 10, 'new.exe': 25})
        old = [p for p in self.m.procs.values() if p.name == 'old.exe'][0]
        self.assertEqual(old.endpoints[('TCP', '1.1.1.1', 443, False)].sent, 10)

    def test_out_of_order_packets_keep_first_and_last_time(self):
        # отчёт 1.5, п. 3: пакеты одного потока не по порядку
        for ts, size in ((10.0, 10), (20.0, 20), (5.0, 5)):
            traffic(self.m, 100, '1.1.1.1', 443, 50000, sent=size, ts=ts)
        self.m.process_pending()
        ep = proc_by_pid(self.m, 100).endpoints[('TCP', '1.1.1.1', 443, False)]
        self.assertEqual((ep.first, ep.last, ep.sent), (5.0, 20.0, 35))
        traffic(self.m, 100, '1.1.1.1', 443, 50000, sent=1, ts=4.0)      # ещё раньше, другая пачка
        self.m.process_pending()
        self.assertEqual((ep.first, ep.last), (4.0, 20.0))

    def test_snapshot_name_is_not_given_to_ended_record(self):
        # процесс известен только по пакетам и уже завершился; снимок показывает следующего
        # владельца PID. Его имя не мешает потом узнать собственный запуск процесса
        traffic(self.m, 100, '1.1.1.1', 443, 50000, sent=10, ts=10.2)
        self.m.on_process_stop(100, 10.5)
        self.m.process_pending()
        self.m.sync_processes({100: ('tool.exe', 1)}, now=11.0)
        old = [p for p in self.m.procs.values() if p.sent == 10][0]
        self.assertEqual((old.name, old.snap_name), ('PID 100', None))
        self.m.on_process_start(100, 10.1, 'C:\\app.exe')                # его запуск дошёл позже
        self.m.process_pending()
        self.assertEqual((old.path, old.started, old.ended, old.sent), ('C:\\app.exe', 10.1, 10.5, 10))

    def test_snapshot_name_goes_to_process_the_snapshot_saw(self):
        # запись заведена пакетом старого процесса; снимок в 11.5 застал уже новый (other.exe,
        # создан в 11.4 — это сообщает Windows). Имя из снимка — нового процесса, а у старой
        # записи по-прежнему можно узнать её собственный запуск
        traffic(self.m, 100, '1.1.1.1', 443, 50000, sent=1, ts=10.96)
        self.m.process_pending()
        self.m.sync_processes({100: ('other.exe', 1)}, now=11.5)
        old = proc_by_pid(self.m, 100)
        self.m.fill_details(old.uid, {'path': 'C:\\other.exe', 'started': 11.4}, now=11.51)
        new = proc_by_pid(self.m, 100)
        self.assertEqual((old.name, old.snap_name, new.snap_name), ('PID 100', None, 'other.exe'))
        self.m.on_process_start(100, 10.74, 'C:\\tool.exe')
        self.m.process_pending()
        self.assertEqual((old.path, old.started, old.sent), ('C:\\tool.exe', 10.74, 1))

    def test_services_seen_stay_with_shared_svchost(self):
        # отчёт 1.5, п. 4: служба остановилась, а общий svchost.exe работает дальше
        self.m.sync_processes({500: ('svchost.exe', 1)}, now=1.0)
        self.m.set_services({500: ['BITS', 'wuauserv']})
        self.m.set_services({500: ['wuauserv']})
        self.assertEqual(proc_by_pid(self.m, 500).services, 'BITS, wuauserv')

    def test_svchost_name_learned_later_asks_for_services(self):
        # отчёт 1.5, п. 4: запись заведена пакетом, имя svchost.exe узнаётся позже
        for learn in ('details', 'snapshot', 'start'):
            m = self._fresh()
            traffic(m, 500, '1.1.1.1', 443, 50000, sent=10, ts=10.0)
            m.process_pending()
            m.set_services({})
            self.assertFalse(m.want_services(), learn)
            if learn == 'details':
                m.fill_details(proc_by_pid(m, 500).uid, {'path': SVCHOST, 'started': 9.0}, now=10.5)
            elif learn == 'snapshot':
                m.sync_processes({500: ('svchost.exe', 1)}, now=10.5)
            else:
                m.on_process_start(500, 9.9, SVCHOST)
                m.process_pending()
            self.assertTrue(m.want_services(), learn)

    def test_group_views(self):
        for pid in (10, 11):
            traffic(self.m, pid, '8.8.8.8', 443, 50000 + pid, sent=100)
        self.m.process_pending()
        for uid, p in self.m.procs.items():
            self.m.fill_details(uid, {'path': 'C:\\app.exe'})
        self.m.on_process_stop(11, 1001.0)
        self.m.process_pending()
        (g,) = group_views(self.m.view())
        self.assertEqual((g.count, g.running, g.sent, g.pids), (2, 1, 200, [10]))
        self.assertEqual(self.m.distinct_endpoints(g.uids, True), 1)


class RandomHistoriesTest(unittest.TestCase):
    """Случайные истории одного PID с известной правдой.

    Несколько процессов подряд получают один PID; события ETW доходят с задержкой и не по
    порядку, часть событий о запуске и завершении теряется, раз в 2 секунды делается снимок
    процессов. Каждый пакет должен попасть в запись своего процесса — и тогда, когда события
    задерживаются дольше, чем длится промежуток между процессами (отчёт 1.5, п. 1): у каждого
    процесса свой локальный порт, как у настоящих программ. Пакеты экземпляра номер k имеют
    размер 1000**k, поэтому по сумме байт записи видно, чьи пакеты и сколько в неё попало.
    """

    PATHS = ('C:\\A\\app.exe', 'C:\\B\\app.exe', 'C:\\A\\tool.exe', 'C:\\C\\other.exe')

    def history(self, rng, gap, life):
        truth, t = [], 10.0 + rng.random() * 3
        count = 1 + int(rng.random() * 5)
        for k in range(count):
            created = t
            start = created + rng.random() * 0.004
            lived = life[0] + rng.random() * (life[1] - life[0])
            running = k == count - 1 and rng.random() < 0.5
            packets = sorted(start + 0.001 + rng.random() * (lived - 0.002)
                             for _ in range(int(rng.random() * 7)))
            truth.append({'created': created, 'start': start, 'packets': packets,
                          'stop': None if running else start + lived,
                          'path': self.PATHS[int(rng.random() * len(self.PATHS))]})
            t = start + lived + gap + rng.random() * 3
        return truth

    @staticmethod
    def alive(truth, moment):
        for k, inst in enumerate(truth):
            if inst['created'] <= moment and (inst['stop'] is None or moment < inst['stop']):
                return k
        return None

    def play(self, seed, gap, delay, life=(0.2, 6.0), details=True, lose_start=0.0, lose_stop=0.0,
             own_ports=True):
        rng = random.Random(seed)
        truth = self.history(rng, gap, life)
        events = []
        for k, inst in enumerate(truth):
            if rng.random() >= lose_start:
                events.append((inst['start'] + rng.random() * delay, 'start', inst['start'], inst['path']))
            if inst['stop'] is not None and rng.random() >= lose_stop:
                events.append((inst['stop'] + rng.random() * delay, 'stop', inst['stop'], None))
            for ts in inst['packets']:
                events.append((ts + rng.random() * delay, 'packet', ts, (1000 ** k, k)))
        events.sort(key=lambda e: e[0])
        end = max([e[0] for e in events] + [truth[-1]['stop'] or truth[-1]['start']]) + 5.0
        m = Model()
        m.resolve_names = False
        tick, next_snapshot, pos = 9.0, 9.0 + rng.random() * 2, 0
        while tick <= end:             # как рабочий цикл монитора: события, снимок, подробности
            while pos < len(events) and events[pos][0] <= tick:
                _when, kind, ts, extra = events[pos]
                pos += 1
                if kind == 'start':
                    m.on_process_start(100, ts, extra)
                elif kind == 'stop':
                    m.on_process_stop(100, ts)
                else:
                    size, k = extra
                    m.on_traffic(100, 'TCP', True, size, '1.1.1.1', 443, '10.0.0.1',
                                 50000 + k if own_ports else 50000, ts)
            m.process_pending()
            if tick >= next_snapshot:
                next_snapshot = tick + 2.0
                capture = tick + rng.random() * 0.03
                seen = self.alive(truth, capture)
                snapshot = {1: ('other.exe', 0)}
                if seen is not None:
                    snapshot[100] = (truth[seen]['path'].rsplit('\\', 1)[1], 1)
                m.sync_processes(snapshot, capture + rng.random() * 0.005)
                for uid, pid in (m.pending_details() if details else ()):
                    now = capture + 0.006 + rng.random() * 0.002
                    k = self.alive(truth, now) if pid == 100 else None
                    m.fill_details(uid, None if k is None else {'path': truth[k]['path'],
                                                                'started': truth[k]['created']}, now)
            tick = round(tick + 0.5, 3)
        return truth, m

    def problems(self, truth, m):
        found, owners = [], {}
        for p in m.procs.values():
            if p.pid != 100:
                continue
            rest, k, parts = p.sent, 0, []
            while rest:
                rest, count = divmod(rest, 1000)
                if count:
                    parts.append(k)
                    owners.setdefault(k, []).append((p.uid, count))
                k += 1
            if len(parts) > 1:
                found.append('в записи %d смешаны пакеты процессов %s' % (p.uid, parts))
            for k in parts:
                if p.path and p.path != truth[k]['path']:
                    found.append('пакеты процесса %d в записи программы %s' % (k, p.path))
        for k, inst in enumerate(truth):
            if inst['packets'] and [count for _uid, count in owners.get(k, ())] != [len(inst['packets'])]:
                found.append('пакеты процесса %d разошлись: %s' % (k, owners.get(k)))
        current = m.by_pid.get(100)
        if truth[-1]['stop'] is None and (current is None or current.ended is not None):
            found.append('последний процесс работает, а запись завершена')
        if truth[-1]['stop'] is not None and current is not None and current.ended is None:
            found.append('все процессы завершились, а запись считается работающей')
        return found

    def test_every_packet_goes_to_its_own_process(self):
        regimes = (
            ('промежуток от 2 с, задержка событий до 1.5 с', dict(gap=2.0, delay=1.5)),
            ('то же без подробностей от Windows', dict(gap=2.0, delay=1.5, details=False)),
            ('теряется 30% событий о запуске', dict(gap=2.0, delay=1.5, lose_start=0.3)),
            ('теряется 30% событий о завершении', dict(gap=2.0, delay=1.5, lose_stop=0.3)),
            ('процессы живут 0.02–0.5 с', dict(gap=2.0, delay=1.5, life=(0.02, 0.5))),
            ('промежуток от 0.3 с, задержка до 0.25 с', dict(gap=0.3, delay=0.25)),
            ('то же, процессы живут 0.02–0.5 с', dict(gap=0.3, delay=0.25, life=(0.02, 0.5))),
            ('промежуток от 0.05 с, задержка до 0.04 с', dict(gap=0.05, delay=0.04)),
            ('задержка до 1 с дольше промежутка от 0.3 с', dict(gap=0.3, delay=1.0)),
            ('задержка до 1.5 с, промежуток от 0.05 с, процессы живут 0.02–0.5 с',
             dict(gap=0.05, delay=1.5, life=(0.02, 0.5))),
            ('то же, один локальный порт у всех, но задержка меньше промежутка',
             dict(gap=0.3, delay=0.25, life=(0.02, 0.5), own_ports=False)),
        )
        for label, options in regimes:
            for seed in range(150):
                truth, m = self.play(seed, **options)
                self.assertEqual(self.problems(truth, m), [], '%s, история %d' % (label, seed))


class HistoryTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.dir.name, 'h.sqlite3')

    def tearDown(self):
        self.dir.cleanup()

    def _save(self, model):
        st = Storage(self.path)
        st.save(*model.collect_dirty())
        st.close()

    def _load(self):
        st = Storage(self.path)
        m = Model()
        m.resolve_names = False
        m.load_history(st.load())
        st.close()
        return m

    def test_roundtrip_and_reattach(self):
        m = Model()
        m.resolve_names = False
        m.sync_processes({50: ('app.exe', 1), 60: ('gone.exe', 1)}, now=100.0)
        for uid, p in list(m.procs.items()):
            m.fill_details(uid, {'path': 'C:\\%s' % p.name, 'started': 40.0 + p.pid}, now=100.0)
        m.on_dns(50, 'example.com', '93.184.215.14', 0)
        traffic(m, 50, '93.184.215.14', 443, 50000, sent=10, recv=20, ts=101)
        traffic(m, 60, '1.1.1.1', 443, 50001, sent=1, ts=102)
        m.process_pending()
        self._save(m)

        # новый запуск монитора: app.exe (PID 50) всё ещё работает, gone.exe — нет
        m2 = self._load()
        self.assertEqual(len(m2.procs), 2)
        ep = m2.procs[1].endpoints[('TCP', '93.184.215.14', 443, False)]
        self.assertEqual((ep.host, ep.sent, ep.recv), ('example.com', 10, 20))
        m2.sync_processes({50: ('app.exe', 1)}, now=200.0)
        for uid, pid in m2.pending_details():
            m2.fill_details(uid, {'path': 'C:\\app.exe', 'started': 90.0}, now=200.0)
        traffic(m2, 50, '93.184.215.14', 443, 50000, sent=5, ts=201)
        m2.process_pending()
        self.assertEqual(len(m2.procs), 2)                # старая запись продолжена
        app = m2.by_pid[50]
        self.assertEqual((app.uid, app.ended, app.sent), (1, None, 15))
        gone = m2.procs[2]
        self.assertEqual(gone.ended, 102)                 # закончилась на последней активности
        self._save(m2)
        m3 = self._load()
        self.assertEqual(m3.procs[1].sent, 15)
        self.assertEqual(m3.procs[2].ended, 102)

    def test_new_process_with_same_pid_is_not_reattached(self):
        m = Model()
        m.sync_processes({50: ('app.exe', 1)}, now=100.0)
        m.fill_details(1, {'path': 'C:\\app.exe', 'started': 90.0})
        traffic(m, 50, '1.1.1.1', 443, 50000, sent=1, ts=101)
        m.process_pending()
        self._save(m)
        m2 = self._load()
        m2.sync_processes({50: ('app.exe', 1)}, now=200.0)
        (uid, _pid), = m2.pending_details()
        m2.fill_details(uid, {'path': 'C:\\app.exe', 'started': 150.0})   # другое время запуска
        self.assertEqual(len(m2.procs), 2)
        self.assertEqual(m2.procs[1].ended, 101)

    def test_history_is_not_continued_by_another_program(self):
        # отчёт 1.4, V14-2: пока монитор был закрыт, PID достался другой программе с тем же
        # именем файла (другая папка) или тому же exe, запущенному заново
        cases = (('C:\\Other\\app.exe', 100.4), ('C:\\Old\\app.exe', 100.4),
                 ('C:\\Other\\app.exe', 100.0))
        for n, (path, started) in enumerate(cases):
            self.path = os.path.join(self.dir.name, 'case%d.sqlite3' % n)
            before = Model()
            before.resolve_names = False
            before.sync_processes({100: ('app.exe', 1)}, now=100.1)
            before.fill_details(before.by_pid[100].uid,
                                {'path': 'C:\\Old\\app.exe', 'started': 100.0}, now=100.1)
            traffic(before, 100, '1.1.1.1', 443, 50000, sent=10, ts=100.15)
            before.process_pending()
            self._save(before)
            after = self._load()
            after.sync_processes({100: ('app.exe', 1)}, now=101.0)
            after.fill_details(after.by_pid[100].uid, {'path': path, 'started': started}, now=101.0)
            traffic(after, 100, '1.1.1.1', 443, 50000, sent=20, ts=101.01)
            after.process_pending()
            self._save(after)
            st = Storage(self.path)
            saved = sorted((r['path'], r['started'], r['sent']) for r in st.load())
            st.close()
            self.assertEqual(saved, sorted([('C:\\Old\\app.exe', 100.0, 10), (path, started, 20)]),
                             (path, started))

    def test_system_and_processes_with_etw_start_time_continue(self):
        # отчёт 1.5, п. 2: время System — время загрузки, его вычисляют, и оно «плавает»;
        # в прошлый раз запись могла получить время из события о запуске (позже на мс)
        cases = ((4, 'System', 'C:\\Windows\\System32\\ntoskrnl.exe', 1000.0, 1000.0156),
                 (4, 'System', 'C:\\Windows\\System32\\ntoskrnl.exe', 1000.0, 1012.0),
                 (50, 'app.exe', 'C:\\App\\app.exe', 100.01, 100.0))
        for pid, name, path, before, now_started in cases:
            m = Model()
            m.resolve_names = False
            m.load_history([{'id': 1, 'pid': pid, 'name': name, 'path': path, 'cmdline': '',
                             'services': '', 'started': before, 'ended': None, 'first_seen': 1010.0,
                             'last_seen': 1050.0, 'sent': 500, 'recv': 500, 'lo_sent': 0,
                             'lo_recv': 0, 'endpoints': []}])
            m.sync_processes({pid: (name, 0)}, now=1100.0)
            for uid, _pid in m.pending_details():
                m.fill_details(uid, {'path': path, 'started': now_started}, now=1100.0)
            self.assertEqual((len(m.procs), m.by_pid[pid].uid, m.by_pid[pid].sent), (1, 1, 500),
                             (pid, now_started))
        # другая загрузка Windows — другая запись System
        m = Model()
        m.load_history([{'id': 1, 'pid': 4, 'name': 'System', 'path': '', 'cmdline': '',
                         'services': '', 'started': 1000.0, 'ended': None, 'first_seen': 1010.0,
                         'last_seen': 1050.0, 'sent': 5, 'recv': 5, 'lo_sent': 0, 'lo_recv': 0,
                         'endpoints': []}])
        m.sync_processes({4: ('System', 0)}, now=9000.0)
        for uid, _pid in m.pending_details():
            m.fill_details(uid, {'path': '', 'started': 8000.0}, now=9000.0)
        self.assertEqual(len(m.procs), 2)

    def test_reattached_process_keeps_inbound_connections(self):
        # отчёт 1.5, п. 4: после перезапуска монитора принятое соединение остаётся входящим,
        # даже если слушающего сокета уже нет
        rows = [{'id': 1, 'pid': 201, 'name': 'server.exe', 'path': 'C:\\server.exe',
                 'cmdline': '', 'services': '', 'started': 5.0, 'ended': None,
                 'first_seen': 10.0, 'last_seen': 11.0, 'sent': 100, 'recv': 0,
                 'lo_sent': 0, 'lo_recv': 0,
                 'endpoints': [{'proc_id': 1, 'proto': 'TCP', 'ip': '10.0.0.8', 'port': 9000,
                                'inbound': 1, 'host': '', 'sent': 100, 'recv': 0, 'psent': 1,
                                'precv': 0, 'first_seen': 11.0, 'last_seen': 11.0}]}]
        m = Model()
        m.resolve_names = False
        m.load_history(rows)
        m.sync_processes({201: ('server.exe', 1)}, now=20.0)
        m.sync_tcp([], now=20.0)
        for uid, _pid in m.pending_details():
            m.fill_details(uid, {'path': 'C:\\server.exe', 'started': 5.0}, now=20.0)
        traffic(m, 201, '10.0.0.8', 60000, 9000, sent=50, ts=21.0)
        m.process_pending()
        self.assertEqual(list(m.by_pid[201].endpoints), [('TCP', '10.0.0.8', 9000, True)])

    def test_moved_traffic_is_moved_in_history_too(self):
        # пачка трафика, уже сохранённая у прежнего процесса, переписана новому: в истории
        # у прежнего не остаётся ни адресата, ни записи без сети
        m = Model()
        m.resolve_names = False
        m.on_process_start(100, 1.0, 'C:\\old.exe')
        traffic(m, 100, '1.1.1.1', 443, 50000, sent=10, ts=2.0)
        traffic(m, 100, '2.2.2.2', 443, 50001, sent=25, ts=3.3)
        m.process_pending()
        self._save(m)
        m.on_process_stop(100, 3.0)
        m.on_process_start(100, 3.2, 'C:\\new.exe')
        m.process_pending()
        self._save(m)
        st = Storage(self.path)
        saved = sorted((r['name'], r['sent'], sorted((e['ip'], e['sent']) for e in r['endpoints']))
                       for r in st.load())
        st.close()
        self.assertEqual(saved, [('new.exe', 25, [('2.2.2.2', 25)]), ('old.exe', 10, [('1.1.1.1', 10)])])
        # дошёл запуск mid.exe в 1.5: PID с 1.5 был у него, значит, old.exe завершился раньше,
        # и пакет в 2.0 — его. У old.exe не остаётся сети, и в истории его больше нет
        m.on_process_start(100, 1.5, 'C:\\mid.exe')
        m.process_pending()
        self._save(m)
        st = Storage(self.path)
        self.assertEqual(sorted((r['name'], r['sent'], len(r['endpoints'])) for r in st.load()),
                         [('mid.exe', 10, 1), ('new.exe', 25, 1)])
        st.close()

    def test_failed_save_keeps_deletions(self):
        # отчёт, п. 4: после сбоя записи и повторной удачной записи в БД нет лишней строки
        m = Model()
        m.resolve_names = False
        m.sync_processes({50: ('app.exe', 1)}, now=100.0)
        m.fill_details(1, {'path': 'C:\\app.exe', 'started': 90.0}, now=100.0)
        traffic(m, 50, '1.1.1.1', 443, 50000, sent=10, ts=101.0)
        m.process_pending()
        self._save(m)
        m2 = self._load()
        m2.sync_processes({50: ('app.exe', 1)}, now=200.0)
        traffic(m2, 50, '1.1.1.1', 443, 50000, sent=10, ts=201.0)
        m2.process_pending()
        self._save(m2)                                   # временная запись попала в БД
        (uid, _pid), = m2.pending_details()
        m2.fill_details(uid, {'path': 'C:\\app.exe', 'started': 90.0}, now=202.0)  # слияние

        class Sysinfo:
            def nt_path_to_dos(self, path):
                return path

        storage = Storage(self.path)
        self.addCleanup(storage.close)
        monitor = Monitor(Sysinfo(), storage, rdns=False)
        monitor.model = m2
        real_save, calls = storage.save, []

        def flaky_save(*args):
            calls.append(1)
            if len(calls) == 1:
                raise OSError('диск занят')
            return real_save(*args)
        storage.save = flaky_save
        with self.assertRaises(OSError):
            monitor._flush()
        monitor._flush()
        db = {r['id']: r['sent'] for r in storage.load()}
        self.assertEqual(db, {1: 20})
        self.assertEqual({p.uid: p.sent for p in m2.procs.values()}, db)

    def test_tcp_activity_time_is_saved(self):
        # отчёт, п. 6: тихое открытое соединение продлевает «последнюю активность» и в БД
        m = Model()
        m.resolve_names = False
        m.sync_processes({7: ('a.exe', 1)}, now=100.0)
        m.sync_tcp([(7, 5, LOCAL, 50000, '1.2.3.4', 443)], 100.0)
        self._save(m)
        m.sync_tcp([(7, 5, LOCAL, 50000, '1.2.3.4', 443)], 200.0)
        self._save(m)
        self.assertEqual(self._load().procs[1].last_seen, 200.0)

    def test_snapshot_time_is_taken_after_reading(self):
        # момент «видели живым» — после чтения списка процессов, а не до него
        clock = [1000.0]

        class Sysinfo:
            def nt_path_to_dos(self, path):
                return path

            def processes(self):
                clock[0] += 3.0          # медленный снимок
                return {7: ('a.exe', 1)}

            def tcp_connections(self):
                return []

        monitor = Monitor(Sysinfo(), None, rdns=False)
        with mock.patch('monitor.time') as fake_time:
            fake_time.time.side_effect = lambda: clock[0]
            monitor._snapshot()
        self.assertEqual(monitor.model.by_pid[7].first_seen, 1003.0)

    def test_purge_and_clear(self):
        st = Storage(self.path)
        st.save([(1, 5, 'a', '', '', '', None, 1.0, 1.0, 1.0, 1, 1, 0, 0)],
                [(1, 'TCP', '1.1.1.1', 443, 0, '', 1, 1, 1, 1, 1.0, 1.0)])
        self.assertEqual(st.purge(1), 1)
        self.assertEqual(st.load(), [])
        st.close()


class UtilTest(unittest.TestCase):
    def test_version(self):
        import main
        from version import __version__
        out = io.StringIO()
        with self.assertRaises(SystemExit), contextlib.redirect_stdout(out):
            main.parse_args(['--version'])
        self.assertEqual(out.getvalue().strip(), 'netmon ' + __version__)

    def test_network_image_paths(self):
        from winapi import nt_path_to_dos
        self.assertEqual(nt_path_to_dos('\\Device\\Mup\\srv\\share\\a.exe'), '\\\\srv\\share\\a.exe')
        self.assertEqual(nt_path_to_dos('\\Device\\Mup\\;LanmanRedirector\\;Z:00000000000a1b2c'
                                        '\\srv\\share\\a.exe'), '\\\\srv\\share\\a.exe')
        self.assertEqual(nt_path_to_dos('\\Device\\Mup\\srv'), '\\Device\\Mup\\srv')

    def test_fmt_bytes(self):
        self.assertEqual(fmt_bytes(0), '0 Б')
        self.assertEqual(fmt_bytes(1536), '1,5 КБ')
        self.assertEqual(fmt_bytes(5 * 1024 ** 3), '5,0 ГБ')

    def test_rate_tracker(self):
        r = RateTracker(window=3)
        self.assertEqual(r.update('a', 0, 0, 0), (0.0, 0.0))
        r.update('a', 1, 100, 0)
        r.update('a', 2, 200, 0)
        up, _ = r.update('a', 3, 300, 30)
        self.assertAlmostEqual(up, 100.0)
        up, _ = r.update('a', 10, 300, 30)
        self.assertEqual(up, 0.0)
        r.update('a', 11, 0, 0)   # сброс счётчиков не даёт отрицательной скорости
        self.assertEqual(r.update('a', 12, 50, 0), (50.0, 0.0))

    def test_ip_helpers(self):
        self.assertEqual(parse_dns_results('type:  5 a.b;::ffff:1.2.3.4;2001:DB8::1;junk;'),
                         ['1.2.3.4', '2001:db8::1'])
        self.assertEqual(ip_category('127.0.0.1'), 'loopback')
        self.assertEqual(ip_category('192.168.0.1'), 'lan')
        self.assertEqual(ip_category('224.0.0.251'), 'multicast')
        self.assertEqual(ip_category('8.8.8.8'), 'public')

    def test_tcp_table_parsing(self):
        row4 = (b'\x05\x00\x00\x00' + v4('10.0.0.2') + port(50000) + b'\x00\x00'
                + v4('1.2.3.4') + port(443) + b'\x00\x00' + (1234).to_bytes(4, 'little'))
        raw = (1).to_bytes(4, 'little') + row4
        self.assertEqual(parse_tcp_table_v4(raw), [(1234, 5, '10.0.0.2', 50000, '1.2.3.4', 443)])
        row6 = (socket.inet_pton(socket.AF_INET6, 'fe80::1') + b'\x00' * 4 + port(50001) + b'\x00\x00'
                + socket.inet_pton(socket.AF_INET6, '::ffff:8.8.8.8') + b'\x00' * 4
                + port(853) + b'\x00\x00' + (5).to_bytes(4, 'little') + (99).to_bytes(4, 'little'))
        raw = (1).to_bytes(4, 'little') + row6
        self.assertEqual(parse_tcp_table_v6(raw), [(99, 5, 'fe80::1', 50001, '8.8.8.8', 853)])


if __name__ == '__main__':
    unittest.main()
