"""Модель данных: процессы, их сетевые адресаты и счётчики байт.

Модель не зависит от Windows: события в неё подаёт ETW (etw.py) или
демо-источник (demo.py). Методы on_* вызываются из потока ETW на каждое
событие, поэтому они только накапливают данные; разбор и привязка к
процессам происходят в process_pending() в рабочем потоке.
"""

import bisect
import ntpath
import re
import threading
import time
from collections import deque, namedtuple

from util import ip_category, ip_from_bytes, parse_dns_results

EPHEMERAL_PORT_MIN = 49152   # начало диапазона динамических портов Windows

TCP_STATES = {1: 'CLOSED', 2: 'LISTEN', 3: 'SYN_SENT', 4: 'SYN_RCVD', 5: 'ESTABLISHED',
              6: 'FIN_WAIT1', 7: 'FIN_WAIT2', 8: 'CLOSE_WAIT', 9: 'CLOSING', 10: 'LAST_ACK',
              11: 'TIME_WAIT', 12: 'DELETE_TCB'}
TCP_LISTEN = 2
TCP_ESTABLISHED = 5

SPECIAL_NAMES = {0: 'Ядро (PID 0)', 4: 'System'}
# Допуск (с) для неточных границ: время снимка процессов — момент после конца чтения,
# а ядро ещё недолго отправляет данные уже завершённого процесса. Применяется, только
# если событие не попало точно ни в чьё время жизни.
SLACK = 0.25
INSTANCES_PER_PID = 8  # сколько последних экземпляров с одним PID помнить
# Время создания процесса из Windows, время событий ETW (сеанс пишет системное время)
# и момент, когда мы видели процесс, берутся из одних часов; допуск — только их шаг.
CLOCK_EPS = 0.05
# Событие ETW о запуске пишется тем же системным вызовом, что создаёт процесс: от времени
# создания (GetProcessTimes) до него — миллисекунды. Четверть секунды — с большим запасом.
START_LAG = 0.25
# «Время запуска» System и процесса простоя (PID 4 и 0) — время загрузки Windows. Его не
# читают, а вычисляют по часам и счётчику времени работы, поэтому от запуска к запуску
# монитора оно немного «плавает» (шаг таймера, подстройка часов). Между двумя загрузками
# Windows проходят минуты, так что минута допуска их не спутает.
BOOT_MATCH = 60.0
BOUNDS_PER_PID = 8    # сколько последних запусков/остановок PID помнить в накопителе
STOPS_PER_PID = 16    # сколько последних событий о завершении PID помнить
# Событие о завершении может обогнать событие о запуске и пакеты того же процесса только
# на время доставки событий ETW (секунды); полминуты — с большим запасом.
EARLY_STOP_WINDOW = 30.0
# Сколько секунд (по времени событий) помнить, какому экземпляру записана каждая пачка
# трафика. Если за это время выяснится, что PID тогда принадлежал другому процессу
# (событие о запуске или завершении дошло позже пакетов), пачка переписывается ему.
# Доставка событий ETW занимает до пары секунд, снимок процессов — раз в 2 с.
RECENT_WINDOW = 10.0
_DRIVE_PATH = re.compile(r'^[a-z]:\\')


def _port(value):
    if isinstance(value, (bytes, bytearray)):
        return int.from_bytes(value, 'big')   # в событиях ETW порты в сетевом порядке
    return int(value)


def _default_name(pid):
    return SPECIAL_NAMES.get(pid, 'PID %d' % pid)


def _path_key(path):
    """Полный путь для сравнения, если он вида C:\\…, иначе None.

    Сетевые пути и пути вида \\Device\\… разные функции Windows записывают по-разному
    (подключённый диск, \\Device\\Mup\\;LanmanRedirector\\…), поэтому их не сравниваем.
    """
    if not path:
        return None
    key = path.strip().strip('"').replace('/', '\\').lower()
    if key.startswith('\\\\?\\'):
        key = key[4:]
    return key if _DRIVE_PATH.match(key) else None


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
                 'need_details', 'absent', 'accept_ports', 'own_start', 'adopted', 'etw_seen',
                 'end_exact', 'end_guess', 'exit_known', 'born', 'snap_time', 'own_path')

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
        self.accept_ports = set()   # локальные порты, на которые этот экземпляр принимал TCP
        self.own_start = None       # время события ETW о запуске, принятого за запуск экземпляра
        self.own_path = ''          # образ (exe) из этого события
        self.adopted = frozenset()  # что взято из этого события на веру: 'path', 'started'
        self.etw_seen = None        # самое раннее событие ETW экземпляра: тогда он точно работал
        # ended выводится в Model._settle из событий о завершении и догадок:
        self.end_exact = False      # ended — из события о завершении (или от Windows), а не догадка
        self.end_guess = None       # процесса уже нет (пропал из снимка, PID занят): конец не позже
        self.exit_known = None      # время завершения, которое сообщила Windows (GetProcessTimes)
        self.born = 0               # номер по порядку событий, когда заведена запись
        self.snap_time = None       # когда был снимок, из которого взято snap_name

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
        self.listen_known = False
        self._instances = {}         # pid -> последние экземпляры с этим PID (новые в конце)
        self._stops = {}             # pid -> [(время, номер прихода)] событий о завершении
        self._arrivals = 0           # номер прихода последнего события (поток ETW)
        self._born_at = None         # номер прихода события, которое сейчас обрабатывается
        self._recent = {}            # pid -> [[t0, ключ потока, значения, экземпляр, адресат]]
        self._newest = float('-inf')  # самое позднее время среди пачек трафика
        self._recent_count = 0
        self._conn_uids = set()      # uid процессов с ненулевым числом открытых соединений
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
        self._bounds = {}            # pid -> времена запусков/остановок, известные потоку ETW

    # ============================================= приём событий (поток ETW)

    def on_traffic(self, pid, proto, send, size, daddr, dport, saddr, sport, ts):
        """daddr/dport — удалённый адрес и порт, saddr/sport — наш сокет.

        Адреса — байты (4 или 16), порты — байты в сетевом порядке или int.
        Для приёма UDP etw.py заранее меняет местами поля пакета.
        """
        with self._acc_lock:
            # события разных «жизней» одного PID (до и после перезапуска) не складываются
            # вместе, даже если пришли не по порядку: номер жизни входит в ключ
            bounds = self._bounds.get(pid)
            key = (pid, bisect.bisect_right(bounds, ts) if bounds else 0,
                   proto, daddr, dport, saddr, sport)
            a = self._acc.get(key)
            if a is None:
                self._acc[key] = [size, 1, 0, 0, ts, ts] if send else [0, 0, size, 1, ts, ts]
                return
            if send:
                a[0] += size
                a[1] += 1
            else:
                a[2] += size
                a[3] += 1
            # события приходят не по порядку: храним самое раннее и самое позднее время
            if ts < a[4]:
                a[4] = ts
            elif ts > a[5]:
                a[5] = ts

    def _push(self, item, pid=None, boundary=None):
        # накопленный трафик уходит в очередь раньше следующего события; у каждого элемента
        # очереди — номер прихода (по нему видно, что пришло раньше появления записи)
        with self._acc_lock:
            if self._acc:
                self._arrivals += 1
                self._queue.append(('traffic', self._acc, self._arrivals))
                self._acc = {}
            self._arrivals += 1
            self._queue.append(item + (self._arrivals,))
            if boundary is not None:
                bounds = self._bounds.get(pid)
                if bounds is None:
                    if len(self._bounds) > 100000:
                        self._bounds.clear()
                    bounds = self._bounds[pid] = []
                bisect.insort(bounds, boundary)
                del bounds[:-BOUNDS_PER_PID]

    def on_accept(self, pid, local_port, ts=None):
        self._push(('accept', pid, _port(local_port), ts))

    def on_process_start(self, pid, ts, image):
        self._push(('start', pid, ts, image), pid, ts)

    def on_process_stop(self, pid, ts):
        self._push(('stop', pid, ts), pid, ts)

    def on_dns(self, pid, name, results, ts):
        self._push(('dns', pid, name, results, ts))

    # ================================================ обработка (рабочий поток)

    def process_pending(self):
        """Применяет накопленные события в порядке их времени.

        События Kernel-Process и Kernel-Network доходят из разных буферов ETW и не по
        порядку: пакет нового процесса часто приходит раньше события о его запуске,
        а завершение — раньше пакетов. Внутри пачки (её собирают раз в полсекунду)
        настоящий порядок восстанавливается по времени событий. При одинаковом времени
        запуск идёт раньше пакетов, а завершение — позже. Что пришло в разных пачках,
        разбирают _settle и _reconsider.
        """
        with self._acc_lock:
            items = self._queue
            if self._acc:
                self._arrivals += 1
                items.append(('traffic', self._acc, self._arrivals))
            self._queue = []
            self._acc = {}
        if not items:
            return 0
        events = []
        last_ts = float('-inf')
        for n, item in enumerate(items):
            kind = item[0]
            if kind == 'traffic':
                for key, value in item[1].items():
                    events.append((value[4], 2, n, kind, (key, value), item[2]))
                continue
            ts = item[2] if kind in ('start', 'stop') else item[3] if kind == 'accept' else item[4]
            if ts is None:
                ts = last_ts          # время неизвестно — там же, где пришло
            else:
                last_ts = max(last_ts, ts)
            rank = {'start': 0, 'accept': 1, 'dns': 1, 'stop': 3}[kind]
            events.append((ts, rank, n, kind, item[1:-1], item[-1]))
        events.sort(key=lambda e: e[:3])
        with self.lock:
            try:
                for _ts, _rank, _n, kind, args, arrival in events:
                    self._born_at = arrival
                    if kind == 'traffic':
                        self._apply_flow(*args)
                    elif kind == 'start':
                        self._apply_start(*args)
                    elif kind == 'stop':
                        self._apply_stop(*args, arrival=arrival)
                    elif kind == 'dns':
                        self._apply_dns(*args[:3])
                    else:
                        self._apply_accept(*args)
            finally:
                self._born_at = None
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
        proc.born = self._arrivals if self._born_at is None else self._born_at
        if pid in SPECIAL_NAMES:
            proc.name = SPECIAL_NAMES[pid]
        else:
            self._set_name(proc, name or self.snap_names.get(pid) or _default_name(pid))
        proc.path = path or ''
        proc.started = started
        self.procs[proc.uid] = proc
        self.by_pid[pid] = proc
        instances = self._instances.setdefault(pid, [])
        instances.append(proc)
        del instances[:-INSTANCES_PER_PID]
        self._settle(pid)
        return proc

    def _insert_proc(self, pid, index, ts, name, path):
        """Запись о процессе, который владел PID раньше уже известных (его запуск дошёл
        позже). Текущим владельцем PID она не становится."""
        instances = self._instances[pid]
        if index == 0 and len(instances) >= INSTANCES_PER_PID:
            return            # старше всех, кого помним: такую запись пришлось бы сразу забыть
        proc = Proc(self._next_uid, pid, ts)
        self._next_uid += 1
        proc.born = self._arrivals if self._born_at is None else self._born_at
        proc.name = SPECIAL_NAMES.get(pid) or name or _default_name(pid)
        proc.path = path or ''
        proc.started = proc.own_start = proc.etw_seen = ts
        proc.own_path = path or ''
        proc.need_details = False     # по PID сейчас читаются сведения другого процесса
        self.procs[proc.uid] = proc
        instances.insert(index, proc)
        del instances[:-INSTANCES_PER_PID]
        self._settle(pid)

    def _set_name(self, proc, name):
        proc.name = name
        if name.lower() == 'svchost.exe':
            self._want_services = True     # у svchost.exe нужно узнать службы, и поскорее

    def _guess_end(self, proc, ts):
        """Процесса уже нет (пропал из снимка, его PID занял другой процесс): он завершился
        не позже ts. Точное время даст событие о завершении, если оно есть."""
        if proc.end_guess is None or ts < proc.end_guess:
            proc.end_guess = ts
        if any(p is proc for p in self._instances.get(proc.pid, ())):
            self._settle(proc.pid)
        elif proc.ended is None:
            self._set_end(proc, ts, False)

    @staticmethod
    def _set_end(proc, end, exact):
        if proc.ended == end and proc.end_exact == exact:
            return
        if end is not None and proc.ended is None:
            proc.conns = 0
        proc.ended, proc.end_exact = end, exact
        proc.dirty = True

    def _alive_from(self, proc):
        """Нижняя граница завершения экземпляра: тогда он ещё точно работал (начало жизни)."""
        marks = [proc.first_seen - SLACK]
        if proc.started is not None:
            marks.append(proc.started)
        if proc.etw_seen is not None:
            marks.append(proc.etw_seen)
        return max(marks)

    @staticmethod
    def _begin_of(proc):
        """Момент, когда экземпляр уже существовал: прежний владелец PID к тому времени ушёл."""
        if proc.started is not None:
            return proc.started
        if proc.etw_seen is not None:
            return min(proc.etw_seen, proc.first_seen)
        return proc.first_seen

    def _settle(self, pid):
        """Время завершения экземпляров PID по событиям о завершении и догадкам.

        События о завершении хранятся (последние STOPS_PER_PID) и при каждом изменении
        распределяются заново, поэтому порядок, в котором они дошли, не важен. Экземпляры
        просматриваются от старого к новому; каждому достаётся самое раннее свободное
        событие, которое не раньше, чем экземпляр точно работал, и не позже появления
        следующего владельца PID (а если процесс пропал из снимка — не позже этого).
        Событие, которого не досталось никому, — от процесса, о котором записи нет.
        """
        instances = self._instances.get(pid, ())
        stops = self._stops.get(pid, ())
        used = set()
        for i, proc in enumerate(instances):
            low = self._alive_from(proc)
            high = self._begin_of(instances[i + 1]) if i + 1 < len(instances) else None
            limit = high
            for bound in (proc.end_guess, proc.exit_known):
                if bound is not None:
                    limit = bound + CLOCK_EPS if limit is None else min(limit, bound + CLOCK_EPS)
            end = None
            for j, (ts, seq) in enumerate(stops):
                if j in used or ts < low:
                    continue
                if limit is not None and ts > limit:
                    break
                if seq < proc.born and ts - low > EARLY_STOP_WINDOW:
                    continue   # пришло задолго до записи, а время намного позже её начала
                end = ts
                used.add(j)
                break
            if end is not None or proc.exit_known is not None:
                self._set_end(proc, proc.exit_known if end is None else end, True)
                continue
            guess = proc.end_guess
            if high is not None:
                guess = high if guess is None else min(guess, high)
            # не раньше, чем экземпляр точно работал
            self._set_end(proc, None if guess is None else max(guess, low), False)
        # границы жизни могли сдвинуться (и начало, и конец) — недавний трафик сверяется заново
        if len(instances) > 1 and self._recent.get(pid):
            self._reconsider(pid)

    def _reconsider(self, pid):
        """Недавние пачки трафика PID, которые по нынешним сведениям попали точно во время
        жизни другого экземпляра, переписываются ему.

        Так бывает, когда пакеты обработаны раньше, чем стало известно о смене владельца
        PID: событие о запуске или завершении дошло позже, или время создания процесса
        сообщила Windows.
        """
        instances = self._instances.get(pid, [])
        for entry in self._recent.get(pid, ()):
            t0, key, value, proc, ep_key = entry
            owner, exact = self._instance_at(pid, t0)
            if not exact or owner is None or owner is proc:
                continue
            if not any(p is proc for p in instances):
                continue
            # переписывается, только если это следует из того, что известно точно, а не из
            # догадок о границах: более новый владелец к моменту пакета уже существовал,
            # а более старый — значит, нынешний тогда ещё не существовал
            newer = instances.index(owner) > instances.index(proc)
            if newer and not self._begin_of(owner) < t0:
                continue
            if not newer and not self._begin_of(proc) > t0:
                continue
            self._subtract_flow(proc, ep_key, value)
            entry[3] = owner
            entry[4] = self._add_flow(owner, key, value, count=False)

    def _lifetimes(self, pid):
        """[(экземпляр, начало, конец)] для экземпляров PID в порядке появления.

        Неизвестные границы берутся у соседей: PID не может одновременно принадлежать
        двум процессам, поэтому следующий владелец появился после ухода предыдущего.
        """
        instances = self._instances.get(pid, ())
        result = []
        for i, proc in enumerate(instances):
            begin, end = proc.started, proc.ended
            if begin is None and i > 0:
                begin = instances[i - 1].ended
            if end is None and i + 1 < len(instances):
                end = instances[i + 1].started
            result.append((proc, begin, end))
        return result

    def _instance_at(self, pid, ts):
        """(экземпляр процесса с этим PID для события в момент ts или None, точно ли попадание).

        События ETW из разных буферов могут прийти не по порядку: поздний пакет
        старого процесса не должен записываться новому владельцу PID.
        1. Точное попадание во время жизни, без допусков.
        2. Иначе — последний экземпляр, запущенный не позже ts: процесс не может
           отправить пакет до своего запуска, а данные завершённого процесса ядро
           ещё какое-то время досылает от его имени. Если это последний известный
           экземпляр и он завершился раньше чем за SLACK до ts, PID, видимо, уже
           у нового процесса, о котором мы пока не знаем (None).
        """
        lifetimes = self._lifetimes(pid)
        for proc, begin, end in reversed(lifetimes):
            if (begin is None or begin <= ts) and (end is None or ts <= end):
                return proc, True
        for i in range(len(lifetimes) - 1, -1, -1):
            proc, begin, end = lifetimes[i]
            if begin is not None and ts < begin:
                continue                    # тогда этот процесс ещё не был запущен
            if i + 1 < len(lifetimes) or end is None or ts <= end + SLACK:
                return proc, False
            return None, False
        # раньше всех известных экземпляров
        return (lifetimes[0][0] if lifetimes else None), False

    def _held_until(self, proc):
        """Момент, до которого PID точно принадлежал этому экземпляру.

        Следующий владелец PID появился не раньше: после запуска экземпляра, после
        события ETW от него, после его события о завершении. Время снимка процессов —
        момент после конца чтения, поэтому от него отнимается SLACK.
        """
        marks = [proc.first_seen - SLACK]
        if proc.started is not None:
            marks.append(proc.started)
        if proc.etw_seen is not None:
            marks.append(proc.etw_seen)
        if proc.end_exact:
            marks.append(proc.ended)
        return max(marks)

    def _note_etw(self, proc, ts):
        """Событие ETW в момент ts точно относится к экземпляру: тогда он работал."""
        if proc.etw_seen is None or ts < proc.etw_seen:
            proc.etw_seen = ts
            self._settle(proc.pid)

    def _proc_at(self, pid, ts, etw=False):
        """Экземпляр, которому принадлежит событие; при необходимости создаёт новый.

        etw: ts — время события ETW (пакет, принятое соединение). Если оно попало точно
        во время жизни экземпляра, это запоминается: в тот момент экземпляр работал.
        """
        proc, exact = self._instance_at(pid, ts)
        if proc is None:
            current = self.by_pid.get(pid)
            if current is not None and current.ended is None:
                return current
            # PID свободен или его прежний владелец уже завершился: это новый процесс,
            # о запуске которого мы ещё не знаем. Запись заводит само это событие
            proc, exact = self._new_proc(pid, ts), True
        if etw and exact:
            self._note_etw(proc, ts)
        return proc

    def _other_exe(self, proc, path):
        """Точно ли path — другой exe, чем у записи (если сравнить не с чем — нет).

        Полные пути сравниваются целиком (C:\\Old\\app.exe и C:\\Other\\app.exe — разные
        программы). Если какой-то путь не вида C:\\… (сетевой, \\Device\\…) или неизвестен,
        сравниваются имена файлов. Путь, взятый на веру из запоздавшего события о запуске,
        для сверки не годится: сверяется то, что известно точно.
        """
        if not path or proc.pid in SPECIAL_NAMES:
            return False
        own_path = '' if 'path' in proc.adopted else proc.path
        old_key, new_key = _path_key(own_path), _path_key(path)
        if old_key and new_key:
            return old_key != new_key
        known = proc.snap_name or (ntpath.basename(own_path) if own_path else None)
        base = ntpath.basename(path)
        return bool(known and base and base.lower() != known.lower())

    def _own_start(self, proc, prev, ts, path):
        """Может ли событие о запуске (момент ts, образ path) быть запуском самого proc?

        Так бывает, когда запись создана по снимку процессов или по трафику раньше, чем
        дошло событие ETW о запуске. Этому не должно противоречить ничто известное:
        это тот же exe, запуск раньше завершения и раньше любого момента, когда процесс
        уже работал, но позже, чем PID освободил предыдущий владелец (prev). События ETW
        сравниваются между собой точно; для времени снимка и времени создания из
        GetProcessTimes — допуск на шаг часов.

        Подходящих запусков может прийти несколько (прежние владельцы PID жили доли
        секунды): своим считается самый поздний из них — раз процесс после него работал,
        более ранние относились не к нему.
        """
        if proc.own_start is not None and ts <= proc.own_start:
            return False             # уже принят более поздний запуск
        if self._other_exe(proc, path):
            return False             # запущен другой exe
        if proc.ended is not None and ts >= proc.ended:
            return False             # запущен после завершения записи
        created = None if 'started' in proc.adopted else proc.started
        if created is not None and not (created - CLOCK_EPS <= ts <= created + START_LAG):
            return False             # время создания (GetProcessTimes) не сходится с запуском
        if proc.etw_seen is not None and proc.etw_seen < ts:
            return False             # событие ETW от процесса было раньше этого запуска
        if proc.first_seen + CLOCK_EPS < ts:
            return False             # процесс видели раньше этого запуска
        if prev is not None and ts < self._held_until(prev):
            return False             # тогда PID ещё принадлежал предыдущему владельцу
        return True

    @staticmethod
    def _began_before(proc, ts):
        """Появился ли экземпляр раньше момента ts (где в ts запущен ДРУГОЙ процесс).

        Если да, тот процесс новее экземпляра; если нет — он владел PID раньше.
        """
        if proc.own_start is not None and ts <= proc.own_start:
            return False             # событие раньше собственного запуска экземпляра
        return ((proc.started is not None and proc.started < ts)
                or (proc.etw_seen is not None and proc.etw_seen < ts)
                or (proc.ended is not None and proc.ended <= ts)
                or proc.first_seen < ts)

    def _apply_start(self, pid, ts, image):
        """Событие ETW о запуске: чей это запуск?

        Экземпляры PID просматриваются от нового к старому. Запуск либо «свой» для уже
        существующей записи (она создана по снимку или по трафику раньше, чем дошло
        событие), либо относится к процессу, которого в записях нет. Новая запись
        заводится, только если такой процесс новее всех известных.
        """
        path = self.nt_path(image) if image else ''
        name = ntpath.basename(path) if path else None
        cand = self._resumable.pop(pid, None)
        if cand is not None:
            self._finalize(cand)
        instances = self._instances.get(pid, ())
        last = len(instances) - 1
        for i in range(last, -1, -1):
            proc = instances[i]
            if self._own_start(proc, instances[i - 1] if i else None, ts, path):
                # путь и время запуска берутся из события, только если точных сведений
                # (из GetProcessTimes) нет; более поздний подходящий запуск их заменит
                replaced, replaced_path = proc.own_start, proc.own_path
                proc.own_start, proc.own_path = ts, path
                if path and (not proc.path or 'path' in proc.adopted):
                    proc.path = path
                    self._set_name(proc, name)
                    proc.adopted |= {'path'}
                    proc.dirty = True
                if proc.started is None or 'started' in proc.adopted:
                    proc.started = ts
                    proc.adopted |= {'started'}
                    proc.dirty = True
                self._settle(pid)
                if replaced is not None:
                    # прежний «свой» запуск оказался запуском процесса, который владел PID
                    # раньше: о нём заводится отдельная запись
                    self._insert_proc(pid, instances.index(proc), replaced,
                                      ntpath.basename(replaced_path) or None, replaced_path)
                return
            if self._began_before(proc, ts):
                if i < last:
                    # процесс жил между двумя известными экземплярами: его запуск дошёл позже
                    # запуска следующего. Запись о нём встаёт на своё место
                    self._insert_proc(pid, i + 1, ts, name, path)
                    return
                break        # процесс новее всех известных
        else:
            if instances:
                # запоздавший запуск того, кто владел PID раньше всех известных
                self._insert_proc(pid, 0, ts, name, path)
                return
        cur = self.by_pid.get(pid)
        if cur is not None:
            # PID уже у нового процесса: прежний завершился не позже, а событие об этом
            # потеряно или ещё не дошло
            self._guess_end(cur, ts)
        proc = self._new_proc(pid, ts, name=name, path=path, started=ts)
        proc.own_start = proc.etw_seen = ts     # запись заведена самим событием о запуске
        proc.own_path = path
        self._settle(pid)

    def _apply_stop(self, pid, ts, arrival=None):
        """Событие ETW о завершении. Чьё оно, решает _settle: события о завершении PID
        хранятся и распределяются между экземплярами заново при каждом изменении."""
        if len(self._stops) > 10000:
            self._stops = {p: v for p, v in self._stops.items() if p in self._instances}
        stops = self._stops.setdefault(pid, [])
        bisect.insort(stops, (ts, self._arrivals if arrival is None else arrival))
        del stops[:-STOPS_PER_PID]
        self._settle(pid)

    def _apply_accept(self, pid, port, ts):
        proc = self._proc_at(pid, time.time() if ts is None else ts, ts is not None)
        proc.accept_ports.add(port)

    def _is_inbound(self, proc, proto, lport, rport):
        if proto == 'TCP':
            if (proc.pid, lport) in self.listen_table or lport in proc.accept_ports:
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
        inbound = self._is_inbound(proc, proto, lport, rport)
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

    def _apply_flow(self, key, value):
        """Накопленные пакеты одного потока: (PID, «жизнь», протокол, адреса, порты)."""
        pid = key[0]
        proc = self._proc_at(pid, value[4], True)
        ep_key = self._add_flow(proc, key, value)
        self._remember(key, value, proc, ep_key)

    def _remember(self, key, value, proc, ep_key):
        """Запомнить, кому записана пачка: её ещё можно переписать (см. RECENT_WINDOW)."""
        pid, t0, t1 = key[0], value[4], value[5]
        if t1 > self._newest:
            self._newest = t1
        cutoff = self._newest - RECENT_WINDOW
        entries = self._recent.get(pid)
        if entries is None:
            entries = self._recent[pid] = deque()
        entries.append([t0, key, value, proc, ep_key])
        while entries and entries[0][2][5] < cutoff:
            entries.popleft()            # пачки идут почти по порядку: устаревшие — в начале
        self._recent_count += 1
        if self._recent_count % 5000 == 0:
            for other in list(self._recent):
                kept = deque(e for e in self._recent[other] if e[2][5] >= cutoff)
                if kept:
                    self._recent[other] = kept
                else:
                    del self._recent[other]

    def _subtract_flow(self, proc, ep_key, value):
        """Убрать пачку трафика из экземпляра (она переписывается другому)."""
        s, ps, r, pr, _t0, t1 = value
        ep = proc.endpoints.get(ep_key)
        if ep is None:
            return
        lo = ip_category(ep.ip) == 'loopback'
        ep.sent -= s
        ep.recv -= r
        ep.psent -= ps
        ep.precv -= pr
        proc.sent -= s
        proc.recv -= r
        if lo:
            proc.lo_sent -= s
            proc.lo_recv -= r
        proc.dirty = True
        if ep.sent or ep.recv or ep.psent or ep.precv or ep.conns:
            proc.dirty_eps.add(ep_key)
        else:
            # других пакетов у адресата не было: его не было и у процесса
            del proc.endpoints[ep_key]
            proc.dirty_eps.discard(ep_key)
            if lo:
                proc.lo_eps -= 1
            lst = self._ep_index.get(ep.ip, [])
            lst[:] = [item for item in lst if item[1] is not ep]
            if proc.persisted:
                if proc.has_net:
                    self._deleted.append((proc.uid,) + ep_key)    # строка адресата в истории
                else:
                    self._deleted.append(proc.uid)                # без сети в истории не нужен
                    proc.persisted = False
        if t1 >= proc.last_seen:
            proc.last_seen = max([proc.first_seen] + [e.last for e in proc.endpoints.values()])

    def _add_flow(self, proc, key, value, count=True):
        """Добавить пачку трафика к экземпляру. Возвращает ключ адресата."""
        _pid, _life, proto, daddr, dport, saddr, sport = key
        s, ps, r, pr, t0, t1 = value
        # адреса уже приведены к виду «daddr — удалённый, saddr — наш» (см. etw.py)
        rip, lip = self._ip(daddr), self._ip(saddr)
        rport, lport = _port(dport), _port(sport)
        lcat = ip_category(lip)
        if lcat in ('multicast', 'broadcast'):
            if rip in self.local_ips:
                # наша же групповая рассылка вернулась к нам: показываем группу
                rip, lip, rport, lport = lip, rip, lport, rport
        elif lcat != 'unspecified':
            self.local_ips.add(lip)          # адрес нашего сокета — значит, наш адрес
        ep = self._endpoint(proc, proto, rip, rport, lport, t0)
        ep.sent += s
        ep.recv += r
        ep.psent += ps
        ep.precv += pr
        if t0 < ep.first:
            ep.first = t0
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
        if count:
            self.total_events += ps + pr
        return ep.key

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
        if not snapshot:
            return   # пустой снимок — сбой чтения списка процессов, а не «всё завершилось»
        with self.lock:
            self.snap_names = {pid: item[0] for pid, item in snapshot.items()}
            for pid, proc in list(self.by_pid.items()):
                if pid not in snapshot:
                    proc.absent = True
                    self._guess_end(proc, now)
            for pid, item in snapshot.items():
                name = item[0]
                proc = self.by_pid.get(pid)
                # имя, в котором мы уверены: из прошлого снимка или из пути к exe
                known = None
                if proc is not None:
                    known = proc.snap_name or (ntpath.basename(proc.path) if proc.path else None)
                reused = proc is not None and (
                    (proc.ended is not None and proc.absent) or
                    (pid not in SPECIAL_NAMES and known and name and
                     known.lower() != name.lower()))
                if proc is None or reused:
                    if proc is not None:
                        self._guess_end(proc, now)
                    proc = self._new_proc(pid, now, name=name)
                if proc.snap_name is None and proc.ended is None:
                    # имя из снимка — только работающей записи: у завершившейся в снимке может
                    # быть уже следующий владелец PID, а по имени сверяется, чей это запуск
                    proc.snap_name = name
                    proc.snap_time = now
                    if proc.name.startswith('PID ') and name:
                        self._set_name(proc, name)
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
            for uid in self._conn_uids:
                proc = self.procs.get(uid)
                if proc is not None:
                    proc.conns = 0
            conn_uids = set()
            seen = {}
            for pid, state, lip, lport, rip, rport in rows:
                if state == TCP_LISTEN or not pid or not rport or rip in ('0.0.0.0', '::'):
                    continue
                proc = self.by_pid.get(pid)
                if (proc is None or proc.ended is not None) and pid not in self.snap_names:
                    continue   # процесса с таким PID уже нет — не заводим «призрака»
                proc = self._proc_at(pid, now)
                ep = self._endpoint(proc, 'TCP', rip, rport, lport, now)
                proc.conns += 1
                conn_uids.add(proc.uid)
                if now > proc.last_seen:
                    proc.last_seen = now
                    proc.dirty = True      # «последняя активность» должна попасть в историю
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
            self._conn_uids = conn_uids

    def set_services(self, mapping):
        """mapping: {pid: [имена служб, работающих сейчас]}.

        Службы, которые за время жизни процесса остановились, из записи не убираются:
        трафик, который они успели передать, тоже записан на этот процесс.
        """
        with self.lock:
            self._want_services = False
            for pid, names in mapping.items():
                proc = self.by_pid.get(pid)
                if proc is not None and proc.ended is None:
                    known = set(proc.services.split(', ')) if proc.services else set()
                    text = ', '.join(sorted(known | set(names)))
                    if text != proc.services:
                        proc.services = text
                        proc.dirty = True

    def want_services(self):
        return self._want_services

    def pending_details(self, limit=100):
        with self.lock:
            out = []
            for proc in self.by_pid.values():
                if not proc.need_details:
                    continue
                if proc.ended is not None:
                    proc.need_details = False   # процесс завершён: его PID может быть уже чужим
                    self._drop_candidate(proc.pid)
                    continue
                out.append((proc.uid, proc.pid))
                if len(out) >= limit:
                    break
            return out

    def _same_instance(self, proc, info):
        """Сведения, прочитанные по PID, относятся к этой записи, а не к новому владельцу PID?

        1. Другой exe — другой процесс (см. _other_exe).
        2. Процесс, созданный позже, чем этот экземпляр уже работал (событие ETW от него,
           снимок процессов), — другой экземпляр, как бы быстро ни сменился владелец PID
           и даже если exe тот же самый.
        """
        path = info.get('path')
        if path and self._other_exe(proc, self.nt_path(path)):
            return False
        started = info.get('started')
        if started is None:
            return True
        seen = proc.first_seen if proc.etw_seen is None else min(proc.first_seen, proc.etw_seen)
        return started <= seen + CLOCK_EPS

    def _continues(self, cand, proc):
        """Работающий процесс proc — тот же, что запись cand из прошлого запуска монитора?

        Пока монитор был закрыт, PID мог достаться другой программе, в том числе с тем же
        именем файла, или тому же exe, запущенному заново. Поэтому нужны то же время
        создания (с точностью до START_LAG) и тот же exe: полный путь, если он известен
        у обоих, иначе имя файла. У System и процесса простоя — та же загрузка Windows.
        """
        if not (proc.started and cand.started):
            return False
        if proc.pid in SPECIAL_NAMES:
            # время загрузки Windows: в пределах одной загрузки — то же самое
            return abs(proc.started - cand.started) <= BOOT_MATCH
        # время из GetProcessTimes совпадает точно; если в прошлый раз запись получила время
        # из события ETW о запуске, оно позже времени создания на миллисекунды
        if abs(proc.started - cand.started) > START_LAG:
            return False
        old_key, new_key = _path_key(cand.path), _path_key(proc.path)
        if old_key and new_key:
            return old_key == new_key
        return cand.name.lower() == proc.name.lower()

    def fill_details(self, uid, info, now=None):
        """info: dict(path, started, cmdline[, exited]) или None, если процесса уже нет.

        Сведения читаются по PID уже после того, как запись создана; за это время
        процесс мог завершиться, а PID — достаться другому. Поэтому экземпляр
        сверяется по времени создания, и чужие сведения не попадают в старую запись.
        """
        now = time.time() if now is None else now
        with self.lock:
            proc = self.procs.get(uid)
            if proc is None:
                return
            proc.need_details = False
            if self.by_pid.get(proc.pid) is not proc:
                return
            if proc.ended is not None:
                self._drop_candidate(proc.pid)
                return
            if info is not None and not self._same_instance(proc, info):
                # PID уже принадлежит другому процессу: прежний завершился до его запуска
                old = proc
                ends = [t for t in (info.get('started'), old.last_seen, old.started) if t]
                self._guess_end(old, max(ends) if ends else now)
                proc = self._new_proc(old.pid, now)
                proc.need_details = False
                created = info.get('started')
                if (old.snap_name and old.snap_time is not None and created is not None
                        and created <= old.snap_time):
                    # снимок, давший прежней записи имя, сделан уже при новом процессе:
                    # это имя нового процесса
                    proc.snap_name, proc.snap_time = old.snap_name, old.snap_time
                    if not old.path and old.name == old.snap_name:
                        old.name = _default_name(old.pid)
                    old.snap_name = old.snap_time = None
            cand = self._resumable.pop(proc.pid, None)
            if info is None:
                if cand is not None:
                    self._finalize(cand)
                return
            if info.get('path'):
                proc.path = self.nt_path(info['path'])
                proc.adopted -= {'path'}       # теперь путь известен точно
                if proc.pid not in SPECIAL_NAMES:
                    self._set_name(proc, ntpath.basename(proc.path) or proc.name)
            if info.get('started'):
                proc.started = info['started']
                proc.adopted -= {'started'}
            if info.get('cmdline'):
                proc.cmdline = info['cmdline']
            if info.get('exited'):
                proc.exit_known = info['exited']   # время завершения сообщила сама Windows
            self._settle(proc.pid)
            proc.dirty = True
            if cand is not None:
                if self._continues(cand, proc):
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
                    if ep.inbound and ep.proto == 'TCP':
                        # если процесс продолжится, его принятые соединения — по-прежнему входящие
                        proc.accept_ports.add(ep.port)
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

    def _drop_candidate(self, pid):
        cand = self._resumable.pop(pid, None)
        if cand is not None:
            self._finalize(cand)

    def _finalize(self, cand):
        # кандидат из истории не продолжился в текущем запуске — сохраняем время окончания
        cand.dirty = True

    def _reattach(self, cand, new):
        """Процесс из истории всё ещё работает: продолжаем его старую запись."""
        cand.ended = None
        cand.end_exact = False
        cand.end_guess = new.end_guess
        cand.exit_known = new.exit_known
        cand.born = new.born
        cand.started = new.started or cand.started     # точное время от Windows
        cand.absent = False
        cand.own_start, cand.own_path = new.own_start, new.own_path
        cand.adopted = frozenset()
        cand.etw_seen = new.etw_seen
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
        if new.uid in self._conn_uids:
            self._conn_uids.discard(new.uid)
            self._conn_uids.add(cand.uid)
        cand.accept_ports |= new.accept_ports
        instances = self._instances.get(new.pid, [])
        instances[:] = [cand if p is new else p for p in instances]
        for entry in self._recent.get(new.pid, ()):
            if entry[3] is new:
                entry[3] = cand
        cand.dirty = True
        self.by_pid[new.pid] = cand
        self._settle(new.pid)
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

    def mark_dirty(self, uids, deleted=()):
        """Вернуть изменения и удаления в очередь, если запись в БД не удалась."""
        with self.lock:
            for uid in uids:
                proc = self.procs.get(uid)
                if proc is not None:
                    proc.dirty = True
                    proc.dirty_eps.update(proc.endpoints)
            pending = set(self._deleted)
            self._deleted.extend(uid for uid in deleted if uid not in pending)

    def clear(self):
        with self._acc_lock:
            self._acc = {}
            self._queue = []
            self._bounds.clear()
        with self.lock:
            self.procs.clear()
            self.by_pid.clear()
            self._ep_index.clear()
            self._resumable.clear()
            self._open_eps.clear()
            self._instances.clear()
            self._stops.clear()
            self._recent.clear()
            self._newest = float('-inf')
            self._conn_uids.clear()
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

    def uids_matching_endpoints(self, text, skip_loopback=False):
        """uid процессов, у которых адрес или имя хоста содержит text.

        skip_loopback: обмен внутри компьютера не показывается — по нему и не ищем.
        """
        text = text.lower()
        found = set()
        with self.lock:
            for ip, items in self._ep_index.items():
                if skip_loopback and ip_category(ip) == 'loopback':
                    continue
                ip_hit = text in ip
                for proc, ep in items:
                    if ip_hit or (ep.host and text in ep.host.lower()):
                        found.add(proc.uid)
        return found
