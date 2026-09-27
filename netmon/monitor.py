"""Связывает всё вместе: источник событий, модель, опрос системы и сохранение истории."""

import logging
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from model import Model

log = logging.getLogger('netmon.monitor')


class Resolver:
    """Обратный DNS (PTR) для адресов, имя которых не удалось узнать из DNS-запросов."""

    def __init__(self, model, workers=4):
        self.model = model
        self.pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix='rdns')

    def submit(self, ips):
        for ip in ips:
            self.pool.submit(self._resolve, ip)

    def _resolve(self, ip):
        try:
            host = socket.gethostbyaddr(ip)[0]
        except (OSError, UnicodeError, ValueError):
            return
        if host and host != ip:
            self.model.on_rdns(ip, host.lower())

    def shutdown(self):
        try:
            self.pool.shutdown(wait=False, cancel_futures=True)
        except TypeError:  # Python < 3.9
            self.pool.shutdown(wait=False)


class Monitor:
    SNAPSHOT_EVERY = 2.0
    SERVICES_EVERY = 30.0
    FLUSH_EVERY = 5.0
    STATS_EVERY = 2.0
    RDNS_EVERY = 2.0

    def __init__(self, sysinfo, storage=None, source_factory=None, rdns=True):
        """sysinfo — WinSysInfo или DemoSysInfo; source_factory(model) -> EtwSession/демо."""
        self.model = Model()
        self.model.nt_path = sysinfo.nt_path_to_dos
        self.model.resolve_names = rdns
        self.sysinfo = sysinfo
        self.storage = storage
        self.source_factory = source_factory
        self.source = None
        self.source_error = ''
        self.source_stats = {}
        self.session_start = time.time()
        self.last_error = ''
        self.resolver = Resolver(self.model) if rdns else None
        self._stop = threading.Event()
        self._clear = threading.Event()
        self._thread = None
        self._services_at = 0.0

    @property
    def db_path(self):
        return self.storage.path if self.storage else ''

    def start(self, keep_days=None):
        if self.storage is not None:
            try:
                removed = self.storage.purge(keep_days)
                if removed:
                    log.info('удалено старых записей: %d', removed)
                self.model.load_history(self.storage.load())
            except Exception as exc:
                log.exception('не удалось прочитать историю')
                self.last_error = 'история: %s' % exc
        self.model.local_ips |= self.sysinfo.local_addresses()
        self._snapshot()
        if self.source_factory is not None:
            try:
                self.source = self.source_factory(self.model)
                self.source.start()
            except Exception as exc:
                log.exception('источник событий не запущен')
                self.source = None
                self.source_error = str(exc)
        self._thread = threading.Thread(target=self._loop, name='netmon-worker', daemon=True)
        self._thread.start()

    def stop(self):
        if self.source is not None:
            try:
                self.source.stop()
            except Exception:
                log.exception('ошибка при остановке источника событий')
        self._stop.set()
        if self._thread is not None:
            self._thread.join(15)
        if self.resolver is not None:
            self.resolver.shutdown()
        if self.storage is not None:
            self.storage.close()

    def request_clear(self):
        self._clear.set()

    def status(self):
        stats = dict(self.source_stats)
        stats['source_ok'] = self.source is not None and stats.get('running', True)
        stats['source_error'] = self.source_error or stats.get('error', '')
        stats['error'] = self.last_error
        stats['db'] = self.db_path
        return stats

    # ------------------------------------------------------------- рабочий поток

    def _loop(self):
        next_snapshot = next_flush = next_stats = next_rdns = 0.0
        while True:
            stopping = self._stop.wait(0.5)
            try:
                if self._clear.is_set():
                    self._clear.clear()
                    self.model.clear()
                    if self.storage is not None:
                        self.storage.clear()
                    next_snapshot = 0.0
                self.model.process_pending()
                now = time.time()
                if now >= next_snapshot and not stopping:
                    self._snapshot()
                    next_snapshot = now + self.SNAPSHOT_EVERY
                self._fill_details()
                if (now - self._services_at >= self.SERVICES_EVERY or
                        (self.model.want_services() and now - self._services_at >= 3)):
                    self._services_at = now
                    self.model.set_services(self.sysinfo.services())
                if self.resolver is not None and now >= next_rdns:
                    next_rdns = now + self.RDNS_EVERY
                    self.resolver.submit(self.model.take_rdns_wanted())
                if self.source is not None and now >= next_stats:
                    next_stats = now + self.STATS_EVERY
                    self.source_stats = self.source.stats()
                if stopping or now >= next_flush:
                    next_flush = now + self.FLUSH_EVERY
                    self._flush()
            except Exception as exc:
                log.exception('ошибка в рабочем потоке')
                self.last_error = '%s: %s' % (type(exc).__name__, exc)
            if stopping:
                break

    def _snapshot(self):
        now = time.time()
        self.model.sync_processes(self.sysinfo.processes(), now)
        self.model.sync_tcp(self.sysinfo.tcp_connections(), now)

    def _fill_details(self):
        for uid, pid in self.model.pending_details(100):
            self.model.fill_details(uid, self.sysinfo.details(pid))

    def _flush(self):
        if self.storage is None:
            return
        procs, eps, deleted = self.model.collect_dirty()
        try:
            self.storage.save(procs, eps, deleted)
        except Exception:
            self.model.mark_dirty([row[0] for row in procs])
            raise
