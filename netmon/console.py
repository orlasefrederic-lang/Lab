"""Текстовый режим: живая таблица в консоли и отчёт по сохранённой истории."""

import os
import sys
import time

from model import Model, display_name, group_views
from util import RateTracker, fmt_bytes, fmt_datetime, fmt_rate, fmt_time, ip_category


def _cut(text, width):
    text = str(text)
    return text if len(text) <= width else text[:width - 1] + '…'


def _endpoint_label(e):
    if e.inbound:
        text = '← %s на наш порт %d %s' % (e.ip, e.port, e.proto)
    else:
        text = '→ %s:%d %s' % (e.ip, e.port, e.proto)
    return '%s  (%s)' % (text, e.host) if e.host else text


def _top_endpoints(model, uids, count, include_lo):
    eps = [e for e in model.endpoints_view(uids)
           if include_lo or ip_category(e.ip) != 'loopback']
    eps.sort(key=lambda e: e.sent + e.recv, reverse=True)
    return eps[:count]


def run_console(monitor, keep_days=None, interval=2.0, top=25, hide_lo=True):
    """Каждые interval секунд перерисовывает таблицу самых активных процессов."""
    monitor.start(keep_days)
    if os.name == 'nt':
        os.system('')  # включает обработку ANSI-последовательностей в консоли Windows
    rates = RateTracker(interval * 1.5)
    try:
        while True:
            time.sleep(interval)
            now = time.time()
            rows = []
            for v in monitor.model.view():
                sent = v.sent - v.lo_sent if hide_lo else v.sent
                recv = v.recv - v.lo_recv if hide_lo else v.recv
                up, down = rates.update(v.uid, now, sent, recv) if v.ended is None else (0, 0)
                if sent or recv:
                    rows.append((up + down, sent + recv, v, sent, recv, up, down))
            rows.sort(key=lambda r: (r[0], r[1]), reverse=True)
            st = monitor.status()
            out = ['\x1b[2J\x1b[H',
                   'Сетевая активность программ — %s   (Ctrl+C — выход)' % time.strftime('%H:%M:%S'),
                   ('ETW: событий %s, потеряно %s' % (st.get('events', 0), st.get('lost', 0)))
                   if st.get('source_ok') else 'ETW не работает: %s' % st.get('source_error'),
                   '',
                   '%-34s %7s %-10s %10s %10s %11s %11s  %s' % (
                       'Программа', 'PID', 'Состояние', '↑ сейчас', '↓ сейчас',
                       'Отправлено', 'Получено', 'Главный адресат')]
            for _a, _t, v, sent, recv, up, down in rows[:top]:
                best = _top_endpoints(monitor.model, [v.uid], 1, not hide_lo)
                out.append('%-34s %7d %-10s %10s %10s %11s %11s  %s' % (
                    _cut(display_name(v.name, v.services), 34), v.pid,
                    'работает' if v.ended is None else 'завершена',
                    fmt_rate(up), fmt_rate(down), fmt_bytes(sent), fmt_bytes(recv),
                    _cut(_endpoint_label(best[0]), 60) if best else ''))
            sys.stdout.write('\n'.join(out) + '\n')
            sys.stdout.flush()
    except KeyboardInterrupt:
        pass
    finally:
        print('\nСохранение истории…')
        monitor.stop()
    return 0


def run_report(storage, days=None, top=30, include_lo=False, destinations=5):
    """Печатает, какие программы работали с сетью, сколько байт и куда."""
    since = time.time() - days * 86400 if days else None
    model = Model()
    model.load_history(storage.load(since))
    storage.close()
    views = []
    for v in model.view():
        if not include_lo:
            v = v._replace(sent=v.sent - v.lo_sent, recv=v.recv - v.lo_recv)
        if v.sent or v.recv:
            views.append(v)
    groups = sorted(group_views(views), key=lambda g: g.sent + g.recv, reverse=True)
    print('История: %s' % storage.path)
    print('Период: %s' % ('последние %g дн. (с %s)' % (days, fmt_datetime(since)) if days
                         else 'вся история'))
    if not groups:
        print('\nДанных нет.')
        return 0
    print('Всего: отправлено %s, получено %s, программ: %d\n' % (
        fmt_bytes(sum(g.sent for g in groups)), fmt_bytes(sum(g.recv for g in groups)),
        len(groups)))
    for n, g in enumerate(groups[:top], 1):
        print('%3d. %s' % (n, display_name(g.name, g.services)))
        if g.path:
            print('     %s' % g.path)
        print('     запусков: %d · отправлено %s · получено %s · активность: %s — %s' % (
            g.count, fmt_bytes(g.sent), fmt_bytes(g.recv), fmt_time(g.first_seen),
            fmt_time(g.last_seen)))
        for e in _top_endpoints(model, g.uids, destinations, include_lo):
            print('       %-70s ↑ %-10s ↓ %s' % (_cut(_endpoint_label(e), 70), fmt_bytes(e.sent),
                                                fmt_bytes(e.recv)))
        print()
    if len(groups) > top:
        print('…и ещё программ: %d (параметр --top)' % (len(groups) - top))
    return 0
