"""История в SQLite: какие процессы работали с сетью, куда и сколько байт."""

import os
import sqlite3
import threading
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS processes (
    id         INTEGER PRIMARY KEY,
    pid        INTEGER NOT NULL,
    name       TEXT,
    path       TEXT,
    cmdline    TEXT,
    services   TEXT,
    started    REAL,
    ended      REAL,
    first_seen REAL,
    last_seen  REAL,
    sent       INTEGER DEFAULT 0,
    recv       INTEGER DEFAULT 0,
    lo_sent    INTEGER DEFAULT 0,
    lo_recv    INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS processes_last_seen ON processes(last_seen);
CREATE TABLE IF NOT EXISTS endpoints (
    proc_id    INTEGER NOT NULL,
    proto      TEXT NOT NULL,
    ip         TEXT NOT NULL,
    port       INTEGER NOT NULL,
    inbound    INTEGER NOT NULL,
    host       TEXT,
    sent       INTEGER DEFAULT 0,
    recv       INTEGER DEFAULT 0,
    psent      INTEGER DEFAULT 0,
    precv      INTEGER DEFAULT 0,
    first_seen REAL,
    last_seen  REAL,
    PRIMARY KEY (proc_id, proto, ip, port, inbound)
);
"""

PROC_COLUMNS = ('id', 'pid', 'name', 'path', 'cmdline', 'services', 'started', 'ended',
                'first_seen', 'last_seen', 'sent', 'recv', 'lo_sent', 'lo_recv')
EP_COLUMNS = ('proc_id', 'proto', 'ip', 'port', 'inbound', 'host', 'sent', 'recv', 'psent',
              'precv', 'first_seen', 'last_seen')


def default_data_dir():
    base = os.environ.get('LOCALAPPDATA')
    if not base:
        base = os.path.join(os.path.expanduser('~'), '.local', 'share')
    return os.path.join(base, 'NetActivityMonitor')


class Storage:
    def __init__(self, path):
        self.path = path
        folder = os.path.dirname(os.path.abspath(path))
        os.makedirs(folder, exist_ok=True)
        self._lock = threading.Lock()
        self.conn = sqlite3.connect(path, check_same_thread=False, timeout=10)
        self.conn.execute('PRAGMA journal_mode=WAL')
        self.conn.execute('PRAGMA synchronous=NORMAL')
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def close(self):
        with self._lock:
            self.conn.close()

    def load(self, since=None):
        """Процессы (с адресатами), активные начиная с since (или все)."""
        with self._lock:
            cur = self.conn.cursor()
            if since:
                cur.execute('SELECT %s FROM processes WHERE last_seen >= ? ORDER BY id'
                            % ', '.join(PROC_COLUMNS), (since,))
            else:
                cur.execute('SELECT %s FROM processes ORDER BY id' % ', '.join(PROC_COLUMNS))
            procs = {}
            for row in cur.fetchall():
                item = dict(zip(PROC_COLUMNS, row))
                item['endpoints'] = []
                procs[item['id']] = item
            cur.execute('SELECT %s FROM endpoints' % ', '.join(EP_COLUMNS))
            for row in cur.fetchall():
                item = dict(zip(EP_COLUMNS, row))
                proc = procs.get(item['proc_id'])
                if proc is not None:
                    proc['endpoints'].append(item)
            return list(procs.values())

    def save(self, procs, endpoints, deleted=()):
        if not procs and not endpoints and not deleted:
            return
        with self._lock, self.conn:
            self.conn.executemany(
                'INSERT OR REPLACE INTO processes (%s) VALUES (%s)'
                % (', '.join(PROC_COLUMNS), ', '.join('?' * len(PROC_COLUMNS))), procs)
            self.conn.executemany(
                'INSERT OR REPLACE INTO endpoints (%s) VALUES (%s)'
                % (', '.join(EP_COLUMNS), ', '.join('?' * len(EP_COLUMNS))), endpoints)
            for uid in deleted:
                self.conn.execute('DELETE FROM endpoints WHERE proc_id = ?', (uid,))
                self.conn.execute('DELETE FROM processes WHERE id = ?', (uid,))

    def purge(self, keep_days):
        """Удаляет записи старше keep_days дней. Возвращает число удалённых процессов."""
        if not keep_days or keep_days <= 0:
            return 0
        limit = time.time() - keep_days * 86400
        with self._lock, self.conn:
            self.conn.execute('DELETE FROM endpoints WHERE proc_id IN '
                              '(SELECT id FROM processes WHERE last_seen < ?)', (limit,))
            cur = self.conn.execute('DELETE FROM processes WHERE last_seen < ?', (limit,))
            return cur.rowcount

    def clear(self):
        with self._lock, self.conn:
            self.conn.execute('DELETE FROM endpoints')
            self.conn.execute('DELETE FROM processes')
