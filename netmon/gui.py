"""Окно программы (tkinter)."""

import csv
import ctypes
import json
import logging
import os
import subprocess
import sys
import time
import tkinter as tk
import tkinter.font as tkfont
import webbrowser
from tkinter import filedialog, messagebox, ttk

from model import display_name, group_views
from util import (CATEGORY_LABELS, RateTracker, fmt_bytes, fmt_datetime, fmt_rate, fmt_time,
                  ip_category, port_label)

log = logging.getLogger('netmon.gui')

REFRESH_MS = 1000

PERIODS = [('за всё время', None), ('за текущий сеанс', 'session'), ('за последний час', 3600),
           ('за 24 часа', 86400), ('за 7 дней', 7 * 86400), ('за 30 дней', 30 * 86400)]

# id, заголовок, ширина, выравнивание, растягивается ли
PROC_COLUMNS = [
    ('name', 'Программа', 250, 'w', True),
    ('pid', 'PID', 70, 'e', False),
    ('status', 'Состояние', 175, 'w', False),
    ('sent', 'Отправлено', 110, 'e', False),
    ('recv', 'Получено', 100, 'e', False),
    ('total', 'Всего', 100, 'e', False),
    ('up', '↑ сейчас', 90, 'e', False),
    ('down', '↓ сейчас', 90, 'e', False),
    ('eps', 'Адресов', 85, 'e', False),
    ('started', 'Запущена', 120, 'w', False),
    ('last', 'Активность', 120, 'w', False),
    ('path', 'Путь', 380, 'w', True),
]

EP_COLUMNS = [
    ('dir', 'Направление', 125, 'w', False),
    ('proto', 'Протокол', 95, 'center', False),
    ('ip', 'Адрес', 210, 'w', False),
    ('port', 'Порт', 110, 'w', False),
    ('host', 'Хост', 300, 'w', True),
    ('state', 'TCP-соединение', 150, 'w', False),
    ('sent', 'Отправлено', 110, 'e', False),
    ('recv', 'Получено', 100, 'e', False),
    ('total', 'Всего', 100, 'e', False),
    ('pkts', 'Пакетов', 80, 'e', False),
    ('first', 'Впервые', 120, 'w', False),
    ('last', 'Последний раз', 120, 'w', False),
]


def enable_dpi_awareness():
    if sys.platform != 'win32':
        return
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except (AttributeError, OSError):
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except (AttributeError, OSError):
            pass


class App:
    def __init__(self, root, monitor, demo=False, settings_path=None):
        self.root = root
        self.monitor = monitor
        self.model = monitor.model
        self.demo = demo
        self.settings_path = settings_path
        self.rates = RateTracker(3.0)
        self.sort = ('total', True)
        self.ep_sort = ('total', True)
        self._tree_cache = {}
        self._ep_cache = {}
        self._row_info = {}
        self._group_ids = {}
        self._ep_ids = {}
        self._group_eps_cache = {}
        self._ep_hits = (None, 0.0, set())
        self._search_job = None
        self._tick_job = None
        self._closing = False

        settings = self._load_settings()
        self.var_search = tk.StringVar()
        self.var_period = tk.StringVar(value=PERIODS[settings.get('period', 0)][0]
                                       if 0 <= settings.get('period', 0) < len(PERIODS)
                                       else PERIODS[0][0])
        self.var_running = tk.BooleanVar(value=settings.get('running', False))
        self.var_group = tk.BooleanVar(value=settings.get('group', False))
        self.var_all = tk.BooleanVar(value=settings.get('all', False))
        self.var_hide_lo = tk.BooleanVar(value=settings.get('hide_lo', True))

        root.title('Сетевая активность программ' + (' — ДЕМО' if demo else ''))
        root.geometry(settings.get('geometry') or '1300x820')
        root.minsize(800, 500)
        self._setup_style()
        self._build()
        root.protocol('WM_DELETE_WINDOW', self.close)
        root.bind('<Control-f>', lambda e: self._focus_search())
        root.bind('<F5>', lambda e: self.refresh())
        self.var_search.trace_add('write', lambda *a: self._schedule_refresh(250))
        for var in (self.var_running, self.var_group, self.var_all, self.var_hide_lo):
            var.trace_add('write', lambda *a: self._schedule_refresh(0))
        self._sash = settings.get('sash')

    # ------------------------------------------------------------ построение

    def _setup_style(self):
        style = ttk.Style(self.root)
        if sys.platform != 'win32' and 'clam' in style.theme_names():
            style.theme_use('clam')
        font = tkfont.nametofont('TkDefaultFont')
        style.configure('Treeview', rowheight=int(font.metrics('linespace') * 1.35) + 2)
        style.configure('Status.TLabel', padding=(6, 2))
        style.configure('Error.TLabel', padding=(6, 2), foreground='#b00020')
        style.configure('Summary.TLabel', padding=(2, 4))

    def _build(self):
        root = self.root
        top = ttk.Frame(root, padding=(8, 6, 8, 0))
        top.pack(side='top', fill='x')

        row1 = ttk.Frame(top)
        row1.pack(fill='x')
        ttk.Label(row1, text='Поиск:').pack(side='left')
        self.search_entry = ttk.Entry(row1, textvariable=self.var_search, width=32)
        self.search_entry.pack(side='left', padx=(4, 2))
        self.search_entry.bind('<Escape>', lambda e: self.var_search.set(''))
        ttk.Button(row1, text='×', width=2, command=lambda: self.var_search.set('')).pack(side='left')
        ttk.Label(row1, text='  Активность:').pack(side='left')
        period = ttk.Combobox(row1, textvariable=self.var_period, state='readonly', width=18,
                              values=[p[0] for p in PERIODS])
        period.pack(side='left', padx=4)
        period.bind('<<ComboboxSelected>>', lambda e: self._schedule_refresh(0))
        ttk.Button(row1, text='Очистить историю…', command=self._clear_history).pack(side='right')
        ttk.Button(row1, text='Экспорт в CSV…', command=self._export_csv).pack(side='right', padx=4)

        row2 = ttk.Frame(top)
        row2.pack(fill='x', pady=(4, 0))
        ttk.Checkbutton(row2, text='Группировать по программам',
                        variable=self.var_group).pack(side='left')
        ttk.Checkbutton(row2, text='Только работающие сейчас',
                        variable=self.var_running).pack(side='left', padx=12)
        ttk.Checkbutton(row2, text='Показывать процессы без сетевой активности',
                        variable=self.var_all).pack(side='left')
        ttk.Checkbutton(row2, text='Не учитывать localhost',
                        variable=self.var_hide_lo).pack(side='left', padx=12)

        self.summary = ttk.Label(top, style='Summary.TLabel', text='')
        self.summary.pack(fill='x', pady=(2, 0))

        status = ttk.Frame(root)
        status.pack(side='bottom', fill='x')
        self.status_left = ttk.Label(status, style='Status.TLabel', text='Запуск…')
        self.status_left.pack(side='left', fill='x', expand=True)
        self.status_right = ttk.Label(status, style='Status.TLabel', text='')
        self.status_right.pack(side='right')

        self.paned = ttk.Panedwindow(root, orient='vertical')
        self.paned.pack(fill='both', expand=True, padx=8, pady=(4, 0))

        upper = ttk.Frame(self.paned)
        self.tree = self._make_tree(upper, PROC_COLUMNS, self._sort_by, 'extended')
        self.tree.bind('<<TreeviewSelect>>', lambda e: self._on_select())
        self.tree.bind('<Button-3>', self._proc_menu)
        self.paned.add(upper, weight=3)

        lower = ttk.Frame(self.paned)
        self.details = tk.Text(lower, height=4, wrap='word', relief='flat', borderwidth=0,
                               background=root.cget('background'), padx=4, pady=4,
                               font=tkfont.nametofont('TkDefaultFont'))
        self.details.pack(side='top', fill='x')
        self.details.configure(state='disabled')
        self.ep_title = ttk.Label(lower, text='', padding=(2, 2))
        self.ep_title.pack(side='top', fill='x')
        self.ep_tree = self._make_tree(lower, EP_COLUMNS, self._ep_sort_by, 'browse')
        self.ep_tree.bind('<Button-3>', self._ep_menu)
        self.ep_tree.bind('<Double-1>', lambda e: self._open_ip_info())
        self.paned.add(lower, weight=2)

        for tree in (self.tree, self.ep_tree):
            tree.tag_configure('ended', foreground='#8a8a8a')
            tree.tag_configure('active', foreground='#0b7a0b')
        self._update_headings()
        self._set_details('Выберите программу в списке, чтобы увидеть подробности и адреса, '
                          'с которыми она обменивалась данными.')

    def _make_tree(self, parent, columns, sort_cb, selectmode):
        frame = ttk.Frame(parent)
        frame.pack(fill='both', expand=True)
        tree = ttk.Treeview(frame, columns=[c[0] for c in columns], show='headings',
                            selectmode=selectmode)
        for cid, title, width, anchor, stretch in columns:
            tree.heading(cid, text=title, command=lambda c=cid: sort_cb(c))
            tree.column(cid, width=width, minwidth=40, anchor=anchor, stretch=stretch)
        vsb = ttk.Scrollbar(frame, orient='vertical', command=tree.yview)
        hsb = ttk.Scrollbar(frame, orient='horizontal', command=tree.xview)
        tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        return tree

    # ------------------------------------------------------------ жизненный цикл

    def start(self):
        if self._sash:
            try:
                self.root.update_idletasks()
                self.paned.sashpos(0, int(self._sash))
            except (tk.TclError, ValueError):
                pass
        self.refresh()
        status = self.monitor.status()
        if not self.demo and not status.get('source_ok'):
            messagebox.showwarning(
                'Сбор статистики не запущен',
                'Не удалось подключиться к Event Tracing for Windows:\n\n%s\n\n'
                'Без этого программа видит только открытые TCP-соединения, но не считает байты. '
                'Запустите её от имени администратора.' % (status.get('source_error') or '?'),
                parent=self.root)

    def close(self):
        if self._closing:
            return
        self._closing = True
        for job in (self._tick_job, self._search_job):
            if job:
                self.root.after_cancel(job)
        self._save_settings()
        self.status_left.configure(text='Сохранение истории…')
        self.root.update_idletasks()
        try:
            self.monitor.stop()
        finally:
            self.root.destroy()

    def _schedule_refresh(self, delay):
        if self._search_job:
            self.root.after_cancel(self._search_job)
        self._search_job = self.root.after(delay, self._refresh_now)

    def _refresh_now(self):
        self._search_job = None
        self.refresh(tick=False)

    def refresh(self, tick=True):
        if self._closing:
            return
        if tick and self._tick_job:
            self.root.after_cancel(self._tick_job)
        try:
            now = time.time()
            self._refresh_processes(now)
            self._refresh_endpoints(now)
            self._refresh_status()
        except Exception:
            log.exception('ошибка обновления окна')
        if tick:
            self._tick_job = self.root.after(REFRESH_MS, self.refresh)

    # ------------------------------------------------------------ список процессов

    def _threshold(self, now):
        value = dict(PERIODS).get(self.var_period.get())
        if value == 'session':
            return self.monitor.session_start
        if value:
            return now - value
        return None

    def _endpoint_hits(self, query, now):
        cached_query, when, hits = self._ep_hits
        if cached_query != query or now - when > 5:
            hits = self.model.uids_matching_endpoints(query)
            self._ep_hits = (query, now, hits)
        return hits

    @staticmethod
    def _self_match(v, query):
        return (query in v.name.lower() or query in (v.path or '').lower()
                or query in (v.services or '').lower() or query in (v.cmdline or '').lower()
                or query == str(v.pid))

    def _collect(self, now):
        hide_lo = self.var_hide_lo.get()
        show_all = self.var_all.get()
        only_running = self.var_running.get()
        threshold = self._threshold(now)
        query = self.var_search.get().strip().lower()
        hits = self._endpoint_hits(query, now) if query else set()

        rates = {}
        visible = []
        for v in self.model.view():
            sent = v.sent - v.lo_sent if hide_lo else v.sent
            recv = v.recv - v.lo_recv if hide_lo else v.recv
            n_eps = v.n_eps - v.lo_eps if hide_lo else v.n_eps
            running = v.ended is None
            if running:
                rates[v.uid] = self.rates.update(v.uid, now, sent, recv)
            if not show_all and not (sent or recv or n_eps):
                continue
            if only_running and not running:
                continue
            if threshold and (v.last_seen or 0) < threshold and not (running and show_all):
                continue
            self_match = bool(query) and self._self_match(v, query)
            if query and not self_match and v.uid not in hits:
                continue
            visible.append((v._replace(sent=sent, recv=recv, n_eps=n_eps), self_match))
        self.rates.forget_except(rates)
        return visible, rates, hide_lo, bool(query)

    def _refresh_processes(self, now):
        visible, rates, hide_lo, searching = self._collect(now)
        rows = []
        info = {}
        total_sent = total_recv = total_up = total_down = 0
        if self.var_group.get():
            match = {v.uid: m for v, m in visible}
            for g in group_views([v for v, _m in visible]):
                up = sum(rates.get(u, (0, 0))[0] for u in g.uids)
                down = sum(rates.get(u, (0, 0))[1] for u in g.uids)
                iid = self._group_ids.setdefault(g.key, 'g%d' % len(self._group_ids))
                n_eps = self._group_endpoints(g, hide_lo)
                if g.running:
                    status = 'работает' if g.count == 1 else 'работает: %d из %d' % (g.running, g.count)
                else:
                    status = 'завершена' if g.count == 1 else 'завершена (%d запусков)' % g.count
                pid_text = str(g.pids[0]) if len(g.pids) == 1 else '%d +%d' % (g.pids[0], len(g.pids) - 1)
                rows.append(self._proc_row(iid, display_name(g.name, g.services), pid_text,
                                           g.pids[0], status, g.running > 0, g, up, down, n_eps,
                                           now))
                info[iid] = {'uids': g.uids, 'group': g,
                             'self_match': any(match.get(u) for u in g.uids)}
                total_sent += g.sent
                total_recv += g.recv
                total_up += up
                total_down += down
        else:
            for v, self_match in visible:
                up, down = rates.get(v.uid, (0.0, 0.0))
                running = v.ended is None
                if running:
                    status = 'работает' + (' · TCP: %d' % v.conns if v.conns else '')
                else:
                    status = 'завершена ' + fmt_time(v.ended, now)
                iid = 'p%d' % v.uid
                rows.append(self._proc_row(iid, display_name(v.name, v.services), str(v.pid),
                                           v.pid, status, running, v, up, down, v.n_eps, now))
                info[iid] = {'uids': [v.uid], 'view': v, 'self_match': self_match}
                total_sent += v.sent
                total_recv += v.recv
                total_up += up
                total_down += down

        col, reverse = self.sort
        rows.sort(key=lambda r: r[3][col], reverse=reverse)
        self._row_info = info
        self._sync_tree(self.tree, self._tree_cache, [(r[0], r[1], r[2]) for r in rows])

        what = 'программ' if self.var_group.get() else 'процессов'
        self.summary.configure(text=(
            'В списке %s: %d   ·   отправлено %s   ·   получено %s   ·   сейчас ↑ %s  ↓ %s%s'
            % (what, len(rows), fmt_bytes(total_sent), fmt_bytes(total_recv),
               fmt_rate(total_up) or '0 Б/с', fmt_rate(total_down) or '0 Б/с',
               '   ·   идёт поиск' if searching else '')))

    def _proc_row(self, iid, name, pid_text, pid, status, running, item, up, down, n_eps, now):
        active = running and up + down >= 1
        last = 'сейчас' if active else fmt_time(item.last_seen, now)
        values = (name, pid_text, status, fmt_bytes(item.sent), fmt_bytes(item.recv),
                  fmt_bytes(item.sent + item.recv), fmt_rate(up), fmt_rate(down), n_eps,
                  fmt_time(item.started, now), last, item.path)
        sort = {'name': name.lower(), 'pid': pid, 'status': (running, item.ended or 0),
                'sent': item.sent, 'recv': item.recv, 'total': item.sent + item.recv,
                'up': up, 'down': down, 'eps': n_eps, 'started': item.started or 0,
                'last': item.last_seen or 0, 'path': (item.path or '').lower()}
        tags = ('active',) if active else (() if running else ('ended',))
        return iid, values, tags, sort

    def _group_endpoints(self, group, hide_lo):
        if group.count == 1:
            return group.n_eps
        key = (group.key, hide_lo)
        cached = self._group_eps_cache.get(key)
        if cached is None or cached[0] != group.n_eps:
            cached = (group.n_eps, self.model.distinct_endpoints(group.uids, hide_lo))
            self._group_eps_cache[key] = cached
        return cached[1]

    @staticmethod
    def _sync_tree(tree, cache, rows):
        """Обновляет таблицу на месте (без мерцания и с сохранением выделения)."""
        existing = set(tree.get_children(''))
        wanted = []
        for iid, values, tags in rows:
            wanted.append(iid)
            state = (values, tags)
            if iid in existing:
                if cache.get(iid) != state:
                    tree.item(iid, values=values, tags=tags)
            else:
                tree.insert('', 'end', iid=iid, values=values, tags=tags)
            cache[iid] = state
        keep = set(wanted)
        stale = [iid for iid in existing if iid not in keep]
        if stale:
            tree.delete(*stale)
            for iid in stale:
                cache.pop(iid, None)
        if list(tree.get_children('')) != wanted:
            for index, iid in enumerate(wanted):
                tree.move(iid, '', index)

    # ------------------------------------------------------------ адресаты

    def _selected_info(self):
        return [self._row_info[iid] for iid in self.tree.selection() if iid in self._row_info]

    def _on_select(self):
        self._refresh_endpoints(time.time())

    def _refresh_endpoints(self, now):
        selected = self._selected_info()
        self._update_details(selected, now)
        if not selected:
            self.ep_title.configure(text='')
            self._sync_tree(self.ep_tree, self._ep_cache, [])
            return
        uids = [u for item in selected for u in item['uids']]
        hide_lo = self.var_hide_lo.get()
        query = self.var_search.get().strip().lower()
        filter_eps = bool(query) and not any(item['self_match'] for item in selected)
        rows = []
        total = 0
        for e in self.model.endpoints_view(uids):
            if hide_lo and ip_category(e.ip) == 'loopback':
                continue
            total += 1
            host = e.host or CATEGORY_LABELS.get(ip_category(e.ip), '')
            if filter_eps and query not in e.ip and query not in host.lower():
                continue
            key = (e.proto, e.ip, e.port, e.inbound)
            iid = self._ep_ids.setdefault(key, 'e%d' % len(self._ep_ids))
            state = e.state + (' ×%d' % e.conns if e.conns > 1 else '')
            values = ('← входящее' if e.inbound else '→ исходящее', e.proto, e.ip,
                      port_label(e.port), host, state, fmt_bytes(e.sent), fmt_bytes(e.recv),
                      fmt_bytes(e.sent + e.recv), e.psent + e.precv, fmt_time(e.first, now),
                      fmt_time(e.last, now))
            sort = {'dir': e.inbound, 'proto': e.proto, 'ip': _ip_sort_key(e.ip),
                    'port': e.port, 'host': host.lower(), 'state': e.state, 'sent': e.sent,
                    'recv': e.recv, 'total': e.sent + e.recv, 'pkts': e.psent + e.precv,
                    'first': e.first or 0, 'last': e.last or 0}
            active = now - (e.last or 0) < 5 and (e.sent or e.recv)
            rows.append((iid, values, ('active',) if active else (), sort))
        col, reverse = self.ep_sort
        rows.sort(key=lambda r: r[3][col], reverse=reverse)
        self._sync_tree(self.ep_tree, self._ep_cache, [(r[0], r[1], r[2]) for r in rows])
        if len(selected) == 1:
            first = selected[0]
            item = first.get('view') or first.get('group')
            who = display_name(item.name, item.services)
        else:
            who = 'выбрано строк: %d' % len(selected)
        shown = '' if len(rows) == total else ' (показано %d — по строке поиска)' % len(rows)
        self.ep_title.configure(text='Куда и откуда шли данные — %s: адресов %d%s' % (who, total, shown))

    def _update_details(self, selected, now):
        if not selected:
            self._set_details('Выберите программу в списке, чтобы увидеть подробности и адреса, '
                              'с которыми она обменивалась данными.')
            return
        if len(selected) > 1:
            self._set_details('Выбрано строк: %d. Ниже — их адресаты вместе.' % len(selected))
            return
        item = selected[0]
        lines = []
        if 'group' in item:
            g = item['group']
            lines.append('Путь: %s' % (g.path or '—'))
            if g.services:
                lines.append('Службы: %s' % g.services)
            lines.append('Запусков в списке: %d, работает сейчас: %d. PID: %s. Первая активность: %s, последняя: %s.'
                         % (g.count, g.running, ', '.join(map(str, g.pids[:20])),
                            fmt_datetime(g.first_seen), fmt_datetime(g.last_seen)))
        else:
            v = item['view']
            lines.append('Путь: %s' % (v.path or '—'))
            if v.cmdline:
                lines.append('Командная строка: %s' % v.cmdline)
            if v.services:
                lines.append('Службы: %s' % v.services)
            lines.append('PID %d · запущена: %s · %s · отправлено %s, получено %s'
                         % (v.pid, fmt_datetime(v.started) or 'неизвестно',
                            'работает' if v.ended is None else 'завершена: ' + fmt_datetime(v.ended),
                            fmt_bytes(v.sent), fmt_bytes(v.recv)))
        self._set_details('\n'.join(lines))

    def _set_details(self, text):
        if getattr(self, '_details_text', None) == text:
            return
        self._details_text = text
        self.details.configure(state='normal')
        self.details.delete('1.0', 'end')
        self.details.insert('1.0', text)
        self.details.configure(state='disabled')

    # ------------------------------------------------------------ строка состояния

    def _refresh_status(self):
        st = self.monitor.status()
        if self.demo:
            text, style = 'Демо-режим: процессы и трафик выдуманы.', 'Status.TLabel'
        elif st.get('source_ok'):
            text = 'ETW: работает · событий: %s · потеряно: %s' % (
                _thousands(st.get('events', 0)), _thousands(st.get('lost', 0)))
            style = 'Status.TLabel'
        else:
            text = ('Сбор статистики не работает: %s — видны только открытые TCP-соединения'
                    % (st.get('source_error') or 'нет данных'))
            style = 'Error.TLabel'
        if st.get('error'):
            text += ' · ошибка: %s' % st['error']
            style = 'Error.TLabel'
        self.status_left.configure(text=text, style=style)
        self.status_right.configure(text=('История: %s' % st['db']) if st.get('db')
                                    else 'История не сохраняется')

    # ------------------------------------------------------------ сортировка

    def _sort_by(self, col):
        current, reverse = self.sort
        numeric = col not in ('name', 'path', 'status')
        self.sort = (col, not reverse if col == current else numeric)
        self._update_headings()
        self.refresh(tick=False)

    def _ep_sort_by(self, col):
        current, reverse = self.ep_sort
        numeric = col not in ('ip', 'host', 'proto', 'dir', 'state')
        self.ep_sort = (col, not reverse if col == current else numeric)
        self._update_headings()
        self._refresh_endpoints(time.time())

    def _update_headings(self):
        for tree, columns, (scol, rev) in ((self.tree, PROC_COLUMNS, self.sort),
                                           (self.ep_tree, EP_COLUMNS, self.ep_sort)):
            for cid, title, *_ in columns:
                arrow = (' ▼' if rev else ' ▲') if cid == scol else ''
                tree.heading(cid, text=title + arrow)

    # ------------------------------------------------------------ действия

    def _focus_search(self):
        self.search_entry.focus_set()
        self.search_entry.select_range(0, 'end')

    def _copy(self, text):
        self.root.clipboard_clear()
        self.root.clipboard_append(text or '')

    def _proc_menu(self, event):
        iid = self.tree.identify_row(event.y)
        if not iid:
            return
        if iid not in self.tree.selection():
            self.tree.selection_set(iid)
        info = self._row_info.get(iid)
        if not info:
            return
        item = info.get('view') or info.get('group')
        menu = tk.Menu(self.root, tearoff=False)
        menu.add_command(label='Копировать имя', command=lambda: self._copy(item.name))
        menu.add_command(label='Копировать путь', command=lambda: self._copy(item.path))
        if info.get('view') is not None and item.cmdline:
            menu.add_command(label='Копировать командную строку',
                             command=lambda: self._copy(item.cmdline))
        menu.add_separator()
        menu.add_command(label='Открыть папку программы', command=lambda: _reveal(item.path),
                         state='normal' if item.path else 'disabled')
        menu.tk_popup(event.x_root, event.y_root)

    def _ep_menu(self, event):
        iid = self.ep_tree.identify_row(event.y)
        if not iid:
            return
        self.ep_tree.selection_set(iid)
        values = self.ep_tree.item(iid, 'values')
        menu = tk.Menu(self.root, tearoff=False)
        menu.add_command(label='Копировать адрес', command=lambda: self._copy(values[2]))
        menu.add_command(label='Копировать хост', command=lambda: self._copy(values[4]))
        menu.add_command(label='Копировать строку', command=lambda: self._copy('\t'.join(map(str, values))))
        menu.add_separator()
        menu.add_command(label='Кому принадлежит адрес (ipinfo.io)', command=self._open_ip_info)
        menu.tk_popup(event.x_root, event.y_root)

    def _open_ip_info(self):
        sel = self.ep_tree.selection()
        if sel:
            ip = self.ep_tree.item(sel[0], 'values')[2]
            webbrowser.open('https://ipinfo.io/%s' % ip)

    def _export_csv(self):
        path = filedialog.asksaveasfilename(
            parent=self.root, title='Экспорт в CSV', defaultextension='.csv',
            initialfile='netmon-%s.csv' % time.strftime('%Y%m%d-%H%M'),
            filetypes=[('CSV (Excel)', '*.csv'), ('Все файлы', '*.*')])
        if not path:
            return
        hide_lo = self.var_hide_lo.get()
        count = 0
        try:
            with open(path, 'w', newline='', encoding='utf-8-sig') as f:
                w = csv.writer(f, delimiter=';')
                w.writerow(['Программа', 'PID', 'Путь', 'Службы', 'Запущена', 'Завершена',
                            'Направление', 'Протокол', 'Адрес', 'Порт', 'Хост',
                            'Отправлено, байт', 'Получено, байт', 'Пакетов', 'Впервые',
                            'Последний раз'])
                for iid in self.tree.get_children(''):
                    info = self._row_info.get(iid)
                    if not info:
                        continue
                    item = info.get('view') or info.get('group')
                    pid = item.pid if info.get('view') is not None else ' '.join(map(str, item.pids))
                    head = [item.name, pid, item.path, item.services, fmt_datetime(item.started),
                            fmt_datetime(item.ended)]
                    eps = [e for e in self.model.endpoints_view(info['uids'])
                           if not (hide_lo and ip_category(e.ip) == 'loopback')]
                    eps.sort(key=lambda e: e.sent + e.recv, reverse=True)
                    if not eps:
                        w.writerow(head + [''] * 10)
                    for e in eps:
                        w.writerow(head + ['входящее' if e.inbound else 'исходящее', e.proto,
                                           e.ip, e.port, e.host, e.sent, e.recv,
                                           e.psent + e.precv, fmt_datetime(e.first),
                                           fmt_datetime(e.last)])
                    count += 1
        except OSError as exc:
            messagebox.showerror('Экспорт', 'Не удалось сохранить файл:\n%s' % exc, parent=self.root)
            return
        messagebox.showinfo('Экспорт', 'Сохранено строк верхней таблицы: %d\n%s' % (count, path),
                            parent=self.root)

    def _clear_history(self):
        if not messagebox.askyesno(
                'Очистить историю',
                'Удалить всю накопленную историю — и в окне, и в файле на диске?\n'
                'Счёт начнётся с нуля.', parent=self.root):
            return
        self.monitor.request_clear()
        self.rates = RateTracker(3.0)
        self._group_eps_cache.clear()
        self.root.after(800, lambda: self.refresh(tick=False))

    # ------------------------------------------------------------ настройки

    def _load_settings(self):
        if not self.settings_path:
            return {}
        try:
            with open(self.settings_path, encoding='utf-8') as f:
                data = json.load(f)
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def _save_settings(self):
        if not self.settings_path:
            return
        names = [p[0] for p in PERIODS]
        data = {'group': self.var_group.get(), 'running': self.var_running.get(),
                'all': self.var_all.get(), 'hide_lo': self.var_hide_lo.get(),
                'period': names.index(self.var_period.get()) if self.var_period.get() in names else 0}
        try:
            if self.root.state() == 'normal':
                data['geometry'] = self.root.geometry()
            data['sash'] = self.paned.sashpos(0)
        except tk.TclError:
            pass
        try:
            with open(self.settings_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=1)
        except OSError:
            log.warning('не удалось сохранить настройки', exc_info=True)


def _thousands(n):
    return '{:,}'.format(int(n or 0)).replace(',', ' ')


def _ip_sort_key(ip):
    if ':' in ip:
        return (1, ip)
    try:
        return (0, tuple(int(x) for x in ip.split('.')))
    except ValueError:
        return (2, ip)


def _reveal(path):
    if not path:
        return
    try:
        if sys.platform == 'win32':
            subprocess.Popen(['explorer', '/select,', path])
        else:
            subprocess.Popen(['xdg-open', os.path.dirname(path)])
    except OSError:
        log.warning('не удалось открыть папку', exc_info=True)


def run(monitor, keep_days=None, demo=False, settings_path=None):
    enable_dpi_awareness()
    root = tk.Tk()
    app = App(root, monitor, demo=demo, settings_path=settings_path)
    root.update()
    monitor.start(keep_days)
    app.start()
    root.mainloop()
