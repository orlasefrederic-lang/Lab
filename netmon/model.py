"""Модель данных: процессы, их сетевые адресаты и счётчики байт.

Модель не зависит от Windows: события в неё подаёт ETW (etw.py) или
демо-источник (demo.py). Методы on_* вызываются из потока ETW на каждое
событие, поэтому они только накапливают данные; разбор и привязка к
процессам происходят в process_pending() в рабочем потоке.
"""

import ntpath
import threading
from collections import namedtuple

from util import ip_category, ip_from_bytes, parse_dns_results

EPHEMERAL_PORT_MIN = 49152   # начало диапазона динамических портов Windows

TCP_STATES = {1: 'CLOSED', 2: 'LISTEN', 3: 'SYN_SENT', 4: 'SYN_RCVD', 5: 'ESTABLISHED',
              6: 'FIN_WAIT1', 7: 'FIN_WAIT2', 8: 'CLOSE_WAIT', 9: 'CLOSING', 10: 'LAST_ACK',
              11: 'TIME_WAIT', 12: 'DELETE_TCB'}
TCP_LISTEN = 2
TCP_ESTABLISHED = 5

SPECIAL_NAMES = {0: 'Ядро (PID 0)', 4: 'System'}


def _port(value):
    if isinstance(value, (bytes, bytearray)):
        return int.from_bytes(value, 'big')   # в событиях ETW порты в сетевом порядке
    return int(value)


def _default_name(pid):
    return SPECIAL_NAMES.get(pid, 'PID %d' % pid)


class Endpoint:
    """Адресат процесса: протокол + удалённый IP + порт + направление."""

    __slots__ = ('proto', 'ip', 'port', 'inbound', 'host', 'host_q', 'state', 'conns',
                 'sent', 'recv', 'psent', 'precv', 'first', 'last')

    def __init__(self, proto, ip, port, inbound, ts):
        self.proto = proto
        self.ip = ip
        self.port = port          # удалённый порт, а для входящих — наш (локальный)
        self.inbound = inbound    # True: к нам подключились; False: мы подключались
        self.host = ''
        self.host_q = -1          # качество имени: 2 — DNS этого процесса, 1 — DNS, 0 — PTR
        self.state = ''           # состояние открытого TCP-соединения
        self.conns = 0            # сколько TCP-соединений открыто сейчас
        self.sent = self.recv = self.psent = self.precv = 0
        self.first = self.last = ts

    @property
    def key(self):
        return (self.proto, self.ip, self.port, self.inbound)


class Proc:
    """Один экземпляр процесса (PID + время жизни)."""

    __slots__ = ('uid', 'pid', 'name', 'snap_name', 'path', 'cmdline', 'services', 'started',
                 'ended', 'first_seen', 'last_seen', 'sent', 'recv', 'lo_sent', 'lo_recv',
                 'endpoints', 'lo_eps', 'conns', 'dirty', 'dirty_eps', 'persisted',
                 'need_details', 'absent')

    def __init__(self, uid, pid, ts):
        self.uid = uid
        self.pid = pid
        self.name = _default_name(pid)
        self.snap_name = None
        self.path = ''
        self.cmdline = ''
        self.services = ''
        self.started = None
        self.ended = None
        self.first_seen = ts
        self.last_seen = ts
        self.sent = self.recv = self.lo_sent = self.lo_recv = 0
        self.endpoints = {}
        self.lo_eps = 0
        self.conns = 0
        self.dirty = True
        self.dirty_eps = set()
        self.persisted = False
        self.need_details = True
        self.absent = False

    @property
    def has_net(self):
        return bool(self.sent or self.recv or self.endpoints)


ProcView = namedtuple('ProcView', 'uid pid name path cmdline services started ended first_seen '
                                  'last_seen sent recv lo_sent lo_recv n_eps lo_eps conns')
EndpointView = namedtuple('EndpointView', 'proto ip port inbound host state conns sent recv '
                                          'psent precv first last')
GroupView = namedtuple('GroupView', 'key name path services uids pids count running started '
                                    'ended first_seen last_seen sent recv lo_sent lo_recv n_eps '
                                    'lo_eps conns')


def display_name(name, services):
    return '%s [%s]' % (name, services) if services else name


def group_key(view):
    """Ключ «программы»: путь к exe (или имя) + набор служб (для svchost.exe)."""
    return ((view.path or view.name or '').lower(), view.services or '')


def group_views(views):
    """Объединяет экземпляры процессов одной программы."""
    groups = {}
    order = []
    for v in views:
        key = group_key(v)
        g = groups.get(key)
        if g is None:
            g = groups[key] = {'views': [], 'key': key}
            order.append(key)
        g['views'].append(v)
    result = []
    for key in order:
        members = groups[key]['views']
        running = [v for v in members if v.ended is None]
        latest = max(members, key=lambda v: v.last_seen or 0)
        started = [v.started for v in members if v.started]
        result.append(GroupView(
            key=key, name=latest.name, path=latest.path, services=latest.services,
            uids=[v.uid for v in members], pids=[v.pid for v in running] or [latest.pid],
            count=len(members), running=len(running),
            started=min(started) if started else None,
            ended=None if running else max((v.ended or 0) for v in members),
            first_seen=min(v.first_seen for v in members),
            last_seen=max(v.last_seen for v in members),
            sent=sum(v.sent for v in members), recv=sum(v.recv for v in members),
            lo_sent=sum(v.lo_sent for v in members), lo_recv=sum(v.lo_recv for v in members),
            n_eps=sum(v.n_eps for v in members), lo_eps=sum(v.lo_eps for v in members),
            conns=sum(v.conns for v in members)))
    return result


class Model:
    def __init__(self):
        self.lock = threading.RLock()
        self.procs = {}              # uid -> Proc (вся история)
        self.by_pid = {}             # pid -> Proc (текущий экземпляр с этим PID)
        self._next_uid = 1
        self.snap_names = {}         # pid -> имя exe из последнего снимка процессов
        self.dns_hosts = {}          # ip -> имя из DNS
        self.pid_hosts = {}          # (pid, ip) -> имя, которое разрешал сам процесс
        self.rdns_hosts = {}         # ip -> имя из обратного DNS (PTR)
        self.resolve_names = True
        self._rdns_wanted = set()
        self._rdns_asked = set()
        self._ep_index = {}          # ip -> [(Proc, Endpoint)] для обновления имён
        self.listen_table = set()    # (pid, порт) — слушающие TCP-сокеты
        self.accept_ports = set()    # (pid, порт) — по событиям «принято соединение»
        self.listen_known = False
        self.local_ips = {'127.0.0.1', '::1'}
        self._resumable = {}         # pid -> Proc из истории, который, возможно, ещё работает
        self._deleted = []           # uid, которые нужно удалить из БД
        self._open_eps = set()       # (uid, ключ адресата) с открытыми TCP-соединениями
        self._ipcache = {}
        self._want_services = False
        self.nt_path = lambda path: path
        self.total_events = 0
        # накопитель для потока ETW
        self._acc_lock = threading.Lock()
        self._acc = {}
        self._queue = []

    # ============================================= приём событий (поток ETW)

    def on_traffic(self, pid, proto, send, size, daddr, dport, saddr, sport, ts):
        """daddr/saddr — байты адреса (4 или 16), dport/sport — порт (байты или int)."""
        key = (pid, proto, daddr, dport, saddr, sport)
        with self._acc_lock:
            a = self._acc.get(key)
            if a is None:
                self._acc[key] = [size, 1, 0, 0, ts, ts] if send else [0, 0, size, 1, ts, ts]
            elif send:
                a[0] += size
                a[1] += 1
                a[5] = ts
            else:
                a[2] += size
                a[3] += 1
                a[5] = ts

    def _push(self, item):
        # порядок важен: накопленный трафик — раньше следующего события
        with self._acc_lock:
            if self._acc:
                self._queue.append(('traffic', self._acc))
                self._acc = {}
            self._queue.append(item)

    def on_accept(self, pid, local_port):
        self._push(('accept', pid, _port(local_port)))

    def on_process_start(self, pid, ts, image):
        self._push(('start', pid, ts, image))

    def on_process_stop(self, pid, ts):
        self._push(('stop', pid, ts))

    def on_dns(self, pid, name, results, ts):
        self._push(('dns', pid, name, results))

    # ================================================ обработка (рабочий поток)

    def process_pending(self):
        with self._acc_lock:
            items = self._queue
            if self._acc:
                items.append(('traffic', self._acc))
            self._queue = []
            self._acc = {}
        if not items:
            return 0
        with self.lock:
            for item in items:
                kind = item[0]
                if kind == 'traffic':
                    self._apply_traffic(item[1])
                elif kind == 'start':
                    self._apply_start(*item[1:])
                elif kind == 'stop':
                    self._apply_stop(*item[1:])
                elif kind == 'dns':
                    self._apply_dns(*item[1:])
                elif kind == 'accept':
                    self.accept_ports.add((item[1], item[2]))
        return len(items)

    def _ip(self, raw):
        if isinstance(raw, str):
            return raw
        ip = self._ipcache.get(raw)
        if ip is None:
            if len(self._ipcache) > 200000:
                self._ipcache.clear()
            ip = self._ipcache[raw] = ip_from_bytes(raw)
        return ip

    def _new_proc(self, pid, ts, name=None, path='', started=None):
        proc = Proc(self._next_uid, pid, ts)
        self._next_uid += 1
        if pid in SPECIAL_NAMES:
            proc.name = SPECIAL_NAMES[pid]
        else:
            proc.name = name or self.snap_names.get(pid) or _default_name(pid)
        proc.path = path or ''
        proc.started = started
        self.procs[proc.uid] = proc
        self.by_pid[pid] = proc
        if proc.name.lower() == 'svchost.exe':
            self._want_services = True
        return proc

    def _end(self, proc, ts):
        if proc.ended is None:
            proc.ended = ts
            proc.dirty = True

    def _apply_start(self, pid, ts, image):
        path = self.nt_path(image) if image else ''
        name = ntpath.basename(path) if path else None
        cand = self._resumable.pop(pid, None)
        if cand is not None:
            self._finalize(cand)
        cur = self.by_pid.get(pid)
        if cur is not None and cur.ended is None and cur.first_seen >= ts - 2.0:
            # запись уже создана по снимку процессов или по трафику — это тот же процесс
            if path and not cur.path:
                cur.path = path
                cur.name = name
            if not cur.started:
                cur.started = ts
            return
        if cur is not None:
            self._end(cur, ts)   # событие о завершении прежнего процесса было потеряно
        self._new_proc(pid, ts, name=name, path=path, started=ts)

    def _apply_stop(self, pid, ts):
        proc = self.by_pid.get(pid)
        if proc is not None:
            self._end(proc, ts)

    def _is_inbound(self, pid, proto, lport, rport):
        if proto == 'TCP':
            if (pid, lport) in self.listen_table or (pid, lport) in self.accept_ports:
                return True
            if self.listen_known:
                return False
        # UDP (и TCP до первого чтения таблицы): «наш порт постоянный, чужой — динамический»
        return 0 < lport < EPHEMERAL_PORT_MIN <= rport

    def _best_host(self, pid, ip):
        host = self.pid_hosts.get((pid, ip))
        if host:
            return host, 2
        host = self.dns_hosts.get(ip)
        if host:
            return host, 1
        host = self.rdns_hosts.get(ip)
        if host:
            return host, 0
        return '', -1

    def _endpoint(self, proc, proto, rip, rport, lport, ts):
        inbound = self._is_inbound(proc.pid, proto, lport, rport)
        key = (proto, rip, lport if inbound else rport, inbound)
        ep = proc.endpoints.get(key)
        if ep is None:
            ep = proc.endpoints[key] = Endpoint(proto, rip, key[2], inbound, ts)
            ep.host, ep.host_q = self._best_host(proc.pid, rip)
            self._ep_index.setdefault(rip, []).append((proc, ep))
            cat = ip_category(rip)
            if cat == 'loopback':
                proc.lo_eps += 1
            elif ep.host_q < 0 and self.resolve_names and cat in ('public', 'lan') \
                    and rip not in self._rdns_asked:
                self._rdns_wanted.add(rip)
            proc.dirty_eps.add(key)
        return ep

    def _apply_traffic(self, acc):
        local = self.local_ips
        for (pid, proto, daddr, dport, saddr, sport), (s, ps, r, pr, t0, t1) in acc.items():
            proc = self.by_pid.get(pid)
            if proc is None:
                proc = self._new_proc(pid, t0)
            rip, lip = self._ip(daddr), self._ip(saddr)
            rport, lport = _port(dport), _port(sport)
            if rip in local and lip not in local:
                # защита на случай, если провайдер перепутал «свой» и «чужой» адрес
                rip, lip, rport, lport = lip, rip, lport, rport
            ep = self._endpoint(proc, proto, rip, rport, lport, t0)
            ep.sent += s
            ep.recv += r
            ep.psent += ps
            ep.precv += pr
            if t1 > ep.last:
                ep.last = t1
            proc.sent += s
            proc.recv += r
            if ip_category(rip) == 'loopback':
                proc.lo_sent += s
                proc.lo_recv += r
            if t1 > proc.last_seen:
                proc.last_seen = t1
            proc.dirty = True
            proc.dirty_eps.add(ep.key)
            self.total_events += ps + pr

    def _apply_dns(self, pid, name, results):
        name = name.strip().rstrip('.').lower()
        if not name:
            return
        if len(self.pid_hosts) > 300000:
            self.pid_hosts.clear()
        for ip in parse_dns_results(results):
            self.dns_hosts[ip] = name
            self.pid_hosts[(pid, ip)] = name
            for proc, ep in self._ep_index.get(ip, ()):
                quality = 2 if proc.pid == pid and proc.ended is None else 1
                if quality > ep.host_q:
                    ep.host, ep.host_q = name, quality
                    proc.dirty_eps.add(ep.key)

    def on_rdns(self, ip, host):
        with self.lock:
            self.rdns_hosts[ip] = host
            for proc, ep in self._ep_index.get(ip, ()):
                if ep.host_q < 0:
                    ep.host, ep.host_q = host, 0
                    proc.dirty_eps.add(ep.key)

    def take_rdns_wanted(self, limit=200):
        with self.lock:
            wanted = [ip for ip in self._rdns_wanted if ip not in self.dns_hosts][:limit]
            self._rdns_asked.update(wanted)
            self._rdns_wanted.difference_update(wanted)
            self._rdns_wanted.difference_update(self.dns_hosts.keys() & self._rdns_wanted)
            return wanted

    # ================================================ снимки системы (рабочий поток)

    def sync_processes(self, snapshot, now):
        """snapshot: {pid: (имя exe, pid родителя)}."""
        with self.lock:
            self.snap_names = {pid: item[0] for pid, item in snapshot.items()}
            for pid, proc in self.by_pid.items():
                if pid not in snapshot:
                    proc.absent = True
                    self._end(proc, now)
            for pid, item in snapshot.items():
                name = item[0]
                proc = self.by_pid.get(pid)
                reused = proc is not None and (
                    (proc.ended is not None and proc.absent) or
                    (pid not in SPECIAL_NAMES and proc.snap_name and name and
                     proc.snap_name.lower() != name.lower()))
                if proc is None or reused:
                    if proc is not None:
                        self._end(proc, now)
                    proc = self._new_proc(pid, now, name=name)
                if proc.snap_name is None:
                    proc.snap_name = name
                    if proc.name.startswith('PID ') and name:
                        proc.name = name
            for pid in [pid for pid in self._resumable if pid not in snapshot]:
                self._finalize(self._resumable.pop(pid))

    def sync_tcp(self, rows, now):
        """rows: [(pid, состояние, локальный IP, порт, удалённый IP, порт)]."""
        with self.lock:
            listen = set()
            for pid, state, lip, lport, rip, rport in rows:
                if state == TCP_LISTEN:
                    listen.add((pid, lport))
                elif lip not in ('0.0.0.0', '::'):
                    self.local_ips.add(lip)
            self.listen_table = listen
            self.listen_known = True
            for proc in self.by_pid.values():
                proc.conns = 0
            seen = {}
            for pid, state, lip, lport, rip, rport in rows:
                if state == TCP_LISTEN or not pid or not rport or rip in ('0.0.0.0', '::'):
                    continue
                proc = self.by_pid.get(pid)
                if proc is None:
                    proc = self._new_proc(pid, now)
                ep = self._endpoint(proc, 'TCP', rip, rport, lport, now)
                proc.conns += 1
                if now > proc.last_seen:
                    proc.last_seen = now
                k = (proc.uid, ep.key)
                prev = seen.get(k)
                name = TCP_STATES.get(state, str(state))
                if prev is None:
                    seen[k] = [ep, name, 1]
                else:
                    prev[2] += 1
                    if state == TCP_ESTABLISHED:
                        prev[1] = name
            for k in self._open_eps - seen.keys():
                proc = self.procs.get(k[0])
                ep = proc.endpoints.get(k[1]) if proc else None
                if ep is not None:
                    ep.state, ep.conns = '', 0
            for ep, name, count in seen.values():
                ep.state, ep.conns = name, count
            self._open_eps = set(seen)

    def set_services(self, mapping):
        """mapping: {pid: [имена служб]}."""
        with self.lock:
            self._want_services = False
            for pid, names in mapping.items():
                proc = self.by_pid.get(pid)
                if proc is not None and proc.ended is None:
                    text = ', '.join(sorted(names))
                    if text != proc.services:
                        proc.services = text
                        proc.dirty = True

    def want_services(self):
        return self._want_services

    def pending_details(self, limit=100):
        with self.lock:
            out = []
            for proc in self.by_pid.values():
                if proc.need_details:
                    out.append((proc.uid, proc.pid))
                    if len(out) >= limit:
                        break
            return out

    def fill_details(self, uid, info):
        """info: dict(path, started, cmdline[, exited]) или None, если процесса уже нет."""
        with self.lock:
            proc = self.procs.get(uid)
            if proc is None:
                return
            proc.need_details = False
            cand = self._resumable.pop(proc.pid, None)
            if info is None:
                if cand is not None:
                    self._finalize(cand)
                return
            if info.get('path'):
                proc.path = self.nt_path(info['path'])
                if proc.pid not in SPECIAL_NAMES:
                    proc.name = ntpath.basename(proc.path) or proc.name
            if info.get('started'):
                proc.started = info['started']
            if info.get('cmdline'):
                proc.cmdline = info['cmdline']
            if info.get('exited'):
                self._end(proc, info['exited'])
            proc.dirty = True
            if cand is not None:
                if (proc.started and cand.started and abs(proc.started - cand.started) < 2.0
                        and cand.name.lower() == proc.name.lower()):
                    self._reattach(cand, proc)
                else:
                    self._finalize(cand)

    # ================================================ история (БД)

    def load_history(self, rows):
        """rows — из Storage.load(): словари процессов с ключом 'endpoints'."""
        with self.lock:
            for r in rows:
                proc = Proc(r['id'], r['pid'], r['first_seen'] or 0)
                proc.name = r['name'] or _default_name(proc.pid)
                proc.path = r['path'] or ''
                proc.cmdline = r['cmdline'] or ''
                proc.services = r['services'] or ''
                proc.started = r['started']
                proc.ended = r['ended']
                proc.last_seen = r['last_seen'] or proc.first_seen
                proc.sent, proc.recv = r['sent'] or 0, r['recv'] or 0
                proc.lo_sent, proc.lo_recv = r['lo_sent'] or 0, r['lo_recv'] or 0
                proc.dirty = False
                proc.persisted = True
                proc.need_details = False
                proc.absent = True
                for e in r['endpoints']:
                    ep = Endpoint(e['proto'], e['ip'], e['port'], bool(e['inbound']),
                                  e['first_seen'])
                    ep.host = e['host'] or ''
                    ep.host_q = 1 if ep.host else -1
                    ep.sent, ep.recv = e['sent'] or 0, e['recv'] or 0
                    ep.psent, ep.precv = e['psent'] or 0, e['precv'] or 0
                    ep.last = e['last_seen']
                    proc.endpoints[ep.key] = ep
                    self._ep_index.setdefault(ep.ip, []).append((proc, ep))
                    if ip_category(ep.ip) == 'loopback':
                        proc.lo_eps += 1
                if proc.ended is None:
                    # на момент прошлого выхода процесс работал — может, работает и сейчас
                    proc.ended = proc.last_seen
                    old = self._resumable.get(proc.pid)
                    if old is None or old.last_seen < proc.last_seen:
                        if old is not None:
                            self._finalize(old)
                        self._resumable[proc.pid] = proc
                    else:
                        proc.dirty = True
                self.procs[proc.uid] = proc
                self._next_uid = max(self._next_uid, proc.uid + 1)

    def _finalize(self, cand):
        # кандидат из истории не продолжился в текущем запуске — сохраняем время окончания
        cand.dirty = True

    def _reattach(self, cand, new):
        """Процесс из истории всё ещё работает: продолжаем его старую запись."""
        cand.ended = None
        cand.absent = False
        cand.snap_name = new.snap_name
        cand.path = new.path or cand.path
        cand.cmdline = new.cmdline or cand.cmdline
        cand.services = new.services or cand.services
        cand.sent += new.sent
        cand.recv += new.recv
        cand.lo_sent += new.lo_sent
        cand.lo_recv += new.lo_recv
        cand.conns = new.conns
        cand.last_seen = max(cand.last_seen, new.last_seen)
        for key, ep in new.endpoints.items():
            old = cand.endpoints.get(key)
            lst = self._ep_index.setdefault(ep.ip, [])
            lst[:] = [item for item in lst if item[0] is not new]
            if old is None:
                cand.endpoints[key] = ep
                lst.append((cand, ep))
                if ip_category(ep.ip) == 'loopback':
                    cand.lo_eps += 1
            else:
                old.sent += ep.sent
                old.recv += ep.recv
                old.psent += ep.psent
                old.precv += ep.precv
                old.first = min(old.first, ep.first)
                old.last = max(old.last, ep.last)
                old.state, old.conns = ep.state, ep.conns
                if ep.host_q > old.host_q:
                    old.host, old.host_q = ep.host, ep.host_q
            cand.dirty_eps.add(key)
        self._open_eps = {(cand.uid if uid == new.uid else uid, key)
                          for uid, key in self._open_eps}
        cand.dirty = True
        self.by_pid[new.pid] = cand
        del self.procs[new.uid]
        if new.persisted:
            self._deleted.append(new.uid)

    def collect_dirty(self):
        """Изменённые записи для сохранения в БД (сохраняются только процессы с сетью)."""
        procs, eps = [], []
        with self.lock:
            for proc in self.procs.values():
                if not proc.dirty and not proc.dirty_eps:
                    continue
                if proc.has_net:
                    procs.append((proc.uid, proc.pid, proc.name, proc.path, proc.cmdline,
                                  proc.services, proc.started, proc.ended, proc.first_seen,
                                  proc.last_seen, proc.sent, proc.recv, proc.lo_sent,
                                  proc.lo_recv))
                    for key in proc.dirty_eps:
                        ep = proc.endpoints.get(key)
                        if ep is not None:
                            eps.append((proc.uid, ep.proto, ep.ip, ep.port, int(ep.inbound),
                                        ep.host, ep.sent, ep.recv, ep.psent, ep.precv,
                                        ep.first, ep.last))
                    proc.persisted = True
                proc.dirty = False
                proc.dirty_eps = set()
            deleted, self._deleted = self._deleted, []
        return procs, eps, deleted

    def mark_dirty(self, uids):
        """Вернуть признак «изменён», если запись в БД не удалась."""
        with self.lock:
            for uid in uids:
                proc = self.procs.get(uid)
                if proc is not None:
                    proc.dirty = True
                    proc.dirty_eps.update(proc.endpoints)

    def clear(self):
        with self._acc_lock:
            self._acc = {}
            self._queue = []
        with self.lock:
            self.procs.clear()
            self.by_pid.clear()
            self._ep_index.clear()
            self._resumable.clear()
            self._open_eps.clear()
            self._deleted = []
            self.total_events = 0

    # ================================================ представления для интерфейса

    def view(self):
        with self.lock:
            return [ProcView(p.uid, p.pid, p.name, p.path, p.cmdline, p.services, p.started,
                             p.ended, p.first_seen, p.last_seen, p.sent, p.recv, p.lo_sent,
                             p.lo_recv, len(p.endpoints), p.lo_eps, p.conns)
                    for p in self.procs.values()]

    def endpoints_view(self, uids):
        """Адресаты одного или нескольких процессов (одинаковые складываются)."""
        merged = {}
        with self.lock:
            for uid in uids:
                proc = self.procs.get(uid)
                if proc is None:
                    continue
                for key, ep in proc.endpoints.items():
                    host = ep.host or self._best_host(proc.pid, ep.ip)[0]
                    m = merged.get(key)
                    if m is None:
                        merged[key] = [ep.proto, ep.ip, ep.port, ep.inbound, host, ep.state,
                                       ep.conns, ep.sent, ep.recv, ep.psent, ep.precv,
                                       ep.first, ep.last]
                    else:
                        if not m[4]:
                            m[4] = host
                        if ep.state and (not m[5] or ep.state == 'ESTABLISHED'):
                            m[5] = ep.state
                        m[6] += ep.conns
                        m[7] += ep.sent
                        m[8] += ep.recv
                        m[9] += ep.psent
                        m[10] += ep.precv
                        m[11] = min(m[11], ep.first)
                        m[12] = max(m[12], ep.last)
        return [EndpointView(*m) for m in merged.values()]

    def distinct_endpoints(self, uids, skip_loopback):
        keys = set()
        with self.lock:
            for uid in uids:
                proc = self.procs.get(uid)
                if proc is None:
                    continue
                for key in proc.endpoints:
                    if not (skip_loopback and ip_category(key[1]) == 'loopback'):
                        keys.add(key)
        return len(keys)

    def uids_matching_endpoints(self, text):
        """uid процессов, у которых адрес или имя хоста содержит text."""
        text = text.lower()
        found = set()
        with self.lock:
            for ip, items in self._ep_index.items():
                ip_hit = text in ip
                for proc, ep in items:
                    if ip_hit or (ep.host and text in ep.host.lower()):
                        found.add(proc.uid)
        return found
