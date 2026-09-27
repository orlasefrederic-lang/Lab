"""Демо-режим: выдуманные процессы и трафик.

Нужен, чтобы посмотреть интерфейс без прав администратора или не в Windows:
    python main.py --demo
"""

import random
import socket
import threading
import time

LOCAL_IP = '192.168.1.23'
LAN_PEER = '192.168.1.50'

# pid, имя, путь, командная строка, службы, [(хост, ip, порт, протокол, вес, доля отправки)]
_PROCESSES = [
    (4, 'System', '', '', '', [
        ('', '192.168.1.10', 445, 'TCP', 2, 0.3)]),
    (1204, 'svchost.exe', r'C:\Windows\System32\svchost.exe',
     r'C:\Windows\system32\svchost.exe -k NetworkService -p -s Dnscache', 'Dnscache', [
         ('', '192.168.1.1', 53, 'UDP', 2, 0.4), ('', '1.1.1.1', 53, 'UDP', 1, 0.4)]),
    (2280, 'svchost.exe', r'C:\Windows\System32\svchost.exe',
     r'C:\Windows\system32\svchost.exe -k netsvcs -p', 'BITS, wuauserv', [
         ('download.windowsupdate.com', '23.52.40.19', 443, 'TCP', 6, 0.02),
         ('fe3cr.delivery.mp.microsoft.com', '52.184.215.140', 443, 'TCP', 1, 0.2)]),
    (5520, 'chrome.exe', r'C:\Program Files\Google\Chrome\Application\chrome.exe',
     '"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" --type=utility '
     '--utility-sub-type=network.mojom.NetworkService', '', [
         ('www.youtube.com', '142.250.74.46', 443, 'TCP', 4, 0.05),
         ('rr3---sn-4g5e6nsz.googlevideo.com', '173.194.182.200', 443, 'UDP', 9, 0.03),
         ('github.com', '140.82.121.4', 443, 'TCP', 2, 0.2),
         ('fonts.gstatic.com', '142.250.74.35', 443, 'TCP', 1, 0.1),
         ('yandex.ru', '77.88.55.88', 443, 'TCP', 2, 0.15)]),
    (7312, 'Telegram.exe', r'C:\Users\User\AppData\Roaming\Telegram Desktop\Telegram.exe',
     '"C:\\Users\\User\\AppData\\Roaming\\Telegram Desktop\\Telegram.exe"', '', [
         ('', '149.154.167.51', 443, 'TCP', 3, 0.3), ('', '91.108.56.130', 443, 'TCP', 1, 0.3)]),
    (8120, 'Discord.exe', r'C:\Users\User\AppData\Local\Discord\app-1.0.9163\Discord.exe',
     '', '', [
         ('gateway.discord.gg', '162.159.135.234', 443, 'TCP', 1, 0.4),
         ('', '66.22.231.14', 50001, 'UDP', 4, 0.5)]),
    (9044, 'steam.exe', r'C:\Program Files (x86)\Steam\steam.exe', '', '', [
        ('cache1-fra1.steamcontent.com', '185.25.182.52', 443, 'TCP', 8, 0.01),
        ('api.steampowered.com', '23.64.192.130', 443, 'TCP', 1, 0.3)]),
    (3300, 'OneDrive.exe', r'C:\Users\User\AppData\Local\Microsoft\OneDrive\OneDrive.exe',
     '', '', [('api.onedrive.com', '13.107.42.12', 443, 'TCP', 2, 0.7)]),
    (6400, 'python.exe', r'C:\Python312\python.exe', 'python -m http.server 8000', '', [
        ('', LAN_PEER, 8000, 'TCP-IN', 2, 0.9)]),
    (6888, 'firefox.exe', r'C:\Program Files\Mozilla Firefox\firefox.exe', '', '', [
        ('localhost', '127.0.0.1', 9150, 'TCP', 2, 0.5)]),
]


def _v4(ip):
    return socket.inet_aton(ip)


class DemoSysInfo:
    def __init__(self):
        self._lock = threading.Lock()
        now = time.time()
        self.procs = {}
        for i, (pid, name, path, cmdline, services, flows) in enumerate(_PROCESSES):
            self.procs[pid] = {'name': name, 'path': path, 'cmdline': cmdline,
                               'services': services, 'flows': flows,
                               'started': now - 3600 * 5 + i * 700, 'alive': True}

    def add(self, pid, info):
        with self._lock:
            self.procs[pid] = info

    def kill(self, pid):
        with self._lock:
            if pid in self.procs:
                self.procs[pid]['alive'] = False

    def processes(self):
        with self._lock:
            return {pid: (p['name'], 1) for pid, p in self.procs.items() if p['alive']}

    def details(self, pid):
        with self._lock:
            p = self.procs.get(pid)
            if p is None or not p['alive']:
                return None
            return {'path': p['path'], 'started': p['started'], 'cmdline': p['cmdline']}

    def services(self):
        with self._lock:
            return {pid: p['services'].split(', ') for pid, p in self.procs.items()
                    if p['services'] and p['alive']}

    def tcp_connections(self):
        rows = []
        with self._lock:
            for pid, p in self.procs.items():
                if not p['alive']:
                    continue
                for i, (host, ip, port, proto, _w, _up) in enumerate(p['flows']):
                    if proto == 'TCP':
                        rows.append((pid, 5, LOCAL_IP, 50000 + pid % 1000 + i, ip, port))
                    elif proto == 'TCP-IN':
                        rows.append((pid, 2, '0.0.0.0', port, '0.0.0.0', 0))
                        rows.append((pid, 5, LOCAL_IP, port, ip, 51000 + i))
        return rows

    def local_addresses(self):
        return {'127.0.0.1', '::1', LOCAL_IP}

    def nt_path_to_dos(self, path):
        return path


class DemoSource:
    """Генерирует события так же, как это делает EtwSession."""

    def __init__(self, model, sysinfo):
        self.model = model
        self.sysinfo = sysinfo
        self.events = 0
        self._stop = threading.Event()
        self._thread = None
        self._resolved = set()
        self._rand = random.Random(42)
        self._next_pid = 12000

    def start(self):
        self._thread = threading.Thread(target=self._run, name='demo', daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(2)

    def stats(self):
        return {'events': self.events, 'lost': 0, 'errors': 0, 'running': True, 'error': ''}

    def _emit(self, pid, flow, index, scale=1.0):
        host, ip, port, proto, weight, up = flow
        now = time.time()
        if host and host != 'localhost' and (pid, host) not in self._resolved:
            self._resolved.add((pid, host))
            dns_pid = pid if self._rand.random() < 0.7 else 1204
            self.model.on_dns(dns_pid, host, 'type:  5 edge.%s;::ffff:%s;' % (host, ip), now)
        local = '127.0.0.1' if ip.startswith('127.') else LOCAL_IP
        if proto == 'TCP-IN':
            lport, rport, proto = port, 51000 + index, 'TCP'
        else:
            lport, rport = 50000 + pid % 1000 + index, port
        size = int(self._rand.expovariate(1.0 / (weight * 6000)) * scale) + 60
        send = self._rand.random() < up
        self.model.on_traffic(pid, proto, send, size if send else size * 3, _v4(ip),
                              rport.to_bytes(2, 'big'), _v4(local), lport.to_bytes(2, 'big'), now)
        self.events += 1

    def _run(self):
        next_spawn = time.time() + 3
        short_lived = []
        while not self._stop.wait(0.05):
            with self.sysinfo._lock:
                procs = [(pid, p['flows']) for pid, p in self.sysinfo.procs.items() if p['alive']]
            for pid, flows in procs:
                for i, flow in enumerate(flows):
                    if self._rand.random() < 0.25 * flow[4] / 4:
                        self._emit(pid, flow, i)
            now = time.time()
            if now >= next_spawn:
                # короткоживущий процесс: запустился, скачал файл и завершился
                pid = self._next_pid
                self._next_pid += 4
                path = r'C:\Windows\System32\curl.exe'
                self.sysinfo.add(pid, {'name': 'curl.exe', 'path': path,
                                       'cmdline': 'curl -O https://example.com/file.zip',
                                       'services': '', 'started': now, 'alive': True,
                                       'flows': [('example.com', '93.184.215.14', 443, 'TCP', 5, 0.05)]})
                self.model.on_process_start(pid, now, path)
                short_lived.append((now + 2.5, pid))
                next_spawn = now + 12
            for item in list(short_lived):
                if now >= item[0]:
                    short_lived.remove(item)
                    self.sysinfo.kill(item[1])
                    self.model.on_process_stop(item[1], now)
