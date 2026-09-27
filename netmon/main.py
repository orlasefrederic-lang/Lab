#!/usr/bin/env python3
"""Сетевая активность программ (Windows).

Показывает, какие программы работали и работают с сетью, сколько байт каждая
отправила и получила и с какими адресами (и хостами) обменивалась данными.

    python main.py              окно программы (запросит права администратора)
    python main.py --console    текстовый режим
    python main.py --report     отчёт по сохранённой истории
    python main.py --demo       демо с выдуманными данными
"""

import argparse
import logging
import logging.handlers
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import winapi  # noqa: E402
from monitor import Monitor  # noqa: E402
from storage import Storage, default_data_dir  # noqa: E402

log = logging.getLogger('netmon')


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        prog='netmon',
        description='Показывает, какие программы работают с сетью: сколько байт они '
                    'отправили и получили и с какими адресами.')
    p.add_argument('--demo', action='store_true',
                   help='демо-режим с выдуманными данными (права администратора не нужны)')
    p.add_argument('--console', action='store_true', help='текстовый режим вместо окна')
    p.add_argument('--report', action='store_true',
                   help='напечатать отчёт по сохранённой истории и выйти')
    p.add_argument('--days', type=float, default=None,
                   help='для --report: за сколько последних дней (по умолчанию — вся история)')
    p.add_argument('--top', type=int, default=30,
                   help='для --report и --console: сколько программ показать (30)')
    p.add_argument('--db', help='файл истории (по умолчанию '
                                '%%LOCALAPPDATA%%\\NetActivityMonitor\\history.sqlite3)')
    p.add_argument('--keep-days', type=float, default=90,
                   help='сколько дней хранить историю, 0 — бессрочно (по умолчанию 90)')
    p.add_argument('--no-history', action='store_true', help='не сохранять историю на диск')
    p.add_argument('--no-rdns', action='store_true',
                   help='не узнавать имена адресов через обратный DNS')
    p.add_argument('--no-elevate', action='store_true',
                   help='не запрашивать права администратора')
    p.add_argument('--no-etw-filter', action='store_true',
                   help='не фильтровать события ETW по номерам (для диагностики)')
    p.add_argument('--include-localhost', action='store_true',
                   help='для --report и --console: учитывать обмен внутри компьютера (localhost)')
    return p.parse_args(argv)


def setup_logging(data_dir, to_console):
    handlers = []
    try:
        os.makedirs(data_dir, exist_ok=True)
        handlers.append(logging.handlers.RotatingFileHandler(
            os.path.join(data_dir, 'netmon.log'), maxBytes=1 << 20, backupCount=2,
            encoding='utf-8'))
    except OSError:
        pass
    if to_console and sys.stderr is not None:
        stream = logging.StreamHandler()
        stream.setLevel(logging.WARNING)
        handlers.append(stream)
    logging.basicConfig(level=logging.INFO, handlers=handlers,
                        format='%(asctime)s %(levelname)s %(name)s: %(message)s')


def fail(message, gui):
    """Показывает ошибку: в окне (если запущено без консоли) или в терминале."""
    log.error(message)
    if gui:
        try:
            import tkinter
            from tkinter import messagebox
            root = tkinter.Tk()
            root.withdraw()
            messagebox.showerror('Сетевая активность программ', message)
            root.destroy()
            return 1
        except Exception:
            pass
    if sys.stderr is not None:
        print(message, file=sys.stderr)
    return 1


def main(argv=None):
    args = parse_args(argv)
    gui_mode = not (args.console or args.report)
    data_dir = default_data_dir()
    setup_logging(data_dir, not gui_mode)
    db_name = 'demo-history.sqlite3' if args.demo else 'history.sqlite3'
    db_path = args.db or os.path.join(data_dir, db_name)

    if args.report:
        if not os.path.exists(db_path):
            return fail('История пока пуста: файл %s не найден.' % db_path, False)
        from console import run_report
        return run_report(Storage(db_path), args.days, args.top, args.include_localhost)

    if args.demo:
        from demo import DemoSource, DemoSysInfo
        sysinfo = DemoSysInfo()

        def factory(model):
            return DemoSource(model, sysinfo)
        rdns = False
    else:
        if not winapi.IS_WINDOWS:
            return fail('Программа работает только в Windows. '
                        'Посмотреть интерфейс можно в демо-режиме: python main.py --demo', gui_mode)
        if not winapi.is_admin() and not args.no_elevate:
            try:
                if winapi.relaunch_as_admin():
                    return 0
            except OSError:
                log.exception('не удалось перезапуститься с правами администратора')
            log.warning('работаем без прав администратора: байты считаться не будут')
        if not winapi.acquire_single_instance():
            return fail('Программа уже запущена.', gui_mode)
        from etw import EtwSession
        sysinfo = winapi.WinSysInfo()

        def factory(model):
            return EtwSession(model, use_filter=not args.no_etw_filter)
        rdns = not args.no_rdns

    storage = None
    if not args.no_history:
        try:
            storage = Storage(db_path)
        except Exception as exc:
            log.exception('не удалось открыть файл истории')
            fail('Не удалось открыть файл истории %s:\n%s\n\nПрограмма будет работать без '
                 'сохранения истории.' % (db_path, exc), gui_mode)

    monitor = Monitor(sysinfo, storage, factory, rdns=rdns)
    keep_days = args.keep_days or None

    if args.console:
        from console import run_console
        return run_console(monitor, keep_days, top=args.top, hide_lo=not args.include_localhost)

    try:
        import gui
    except ImportError as exc:
        if sys.stdout is None:
            return fail('Не найден модуль tkinter: %s' % exc, False)
        print('Не найден модуль tkinter (%s) — запускаю текстовый режим.' % exc)
        from console import run_console
        return run_console(monitor, keep_days, top=args.top, hide_lo=not args.include_localhost)
    gui.run(monitor, keep_days, demo=args.demo,
            settings_path=os.path.join(data_dir, 'settings.json'))
    return 0


if __name__ == '__main__':
    sys.exit(main())
