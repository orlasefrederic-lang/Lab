"""Модель: учёт байт, направления, имена хостов, жизненный цикл процессов, история."""

import contextlib
import io
import os
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
