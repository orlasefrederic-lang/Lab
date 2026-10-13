"""Вкладка «Брандмауэр» и окно «Запретить программе доступ в сеть»."""

import ntpath
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from firewall import check_blockable, directions_label, split_services, warnings_for

FW_COLUMNS = [
    ('name', 'Программа', 220, 'w', False),
    ('service', 'Служба', 150, 'w', False),
    ('what', 'Что запрещено', 210, 'w', False),
    ('state', 'Состояние', 170, 'w', False),
    ('path', 'Путь', 520, 'w', True),
]

INTRO = ('Программам из этого списка запрещён доступ в сеть. Запрет делается правилами '
         'Брандмауэра Защитника Windows (группа «NetActivityMonitor»): они действуют, даже когда '
         'монитор закрыт, и сохраняются после перезагрузки. Добавить программу можно и здесь, '
         'и правой кнопкой мыши по строке на вкладке «Сетевая активность».')


def entry_title(entry):
    return ntpath.basename(entry.program) or entry.program


class FirewallTab:
    def __init__(self, parent, app, manager):
        self.app = app
        self.manager = manager
        self.frame = ttk.Frame(parent, padding=(8, 6, 8, 0))
        self._version = -1
        self._entries = {}
        self._cache = {}

        self.intro = ttk.Label(self.frame, text=INTRO, justify='left')
        self.intro.pack(fill='x')
        self.intro.bind('<Configure>', lambda e: self.intro.configure(wraplength=max(300, e.width - 8)))
        self.warning = ttk.Label(self.frame, text='', style='Error.TLabel', justify='left')
        self.warning.pack(fill='x')

        bar = ttk.Frame(self.frame)
        bar.pack(fill='x', pady=(6, 4))
        ttk.Button(bar, text='Запретить программу…', command=self.add).pack(side='left')
        self.btn_remove = ttk.Button(bar, text='Убрать из списка (разрешить)', command=self.remove)
        self.btn_remove.pack(side='left', padx=(6, 0))
        self.btn_pause = ttk.Button(bar, text='Временно разрешить',
                                    command=lambda: self.set_enabled(False))
        self.btn_pause.pack(side='left', padx=(6, 0))
        self.btn_resume = ttk.Button(bar, text='Снова запретить', command=lambda: self.set_enabled(True))
        self.btn_resume.pack(side='left', padx=(6, 0))
        ttk.Button(bar, text='Обновить', command=self.manager.refresh).pack(side='left', padx=(6, 0))
        self.state_label = ttk.Label(bar, text='Загрузка правил…')
        self.state_label.pack(side='right')

        holder = ttk.Frame(self.frame)
        holder.pack(fill='both', expand=True)
        self.tree = app._make_tree(holder, FW_COLUMNS, lambda c: None, 'extended')
        self.tree.tag_configure('paused', foreground='#8a8a8a')
        self.tree.bind('<<TreeviewSelect>>', lambda e: self._update_buttons())
        self.tree.bind('<Delete>', lambda e: self.remove())
        self.tree.bind('<Button-3>', self._menu)
        self._update_buttons()

    # ------------------------------------------------------------ обновление

    def update(self):
        m = self.manager
        if m.version != self._version:
            self._version = m.version
            self._fill()
        if m.busy:
            text = 'Применяю правила брандмауэра…'
        elif m.error:
            text = 'Ошибка: %s' % m.error
        elif m.loaded:
            text = 'Программ в списке: %d' % len(m.entries)
        else:
            text = 'Загрузка правил…'
        self.state_label.configure(text=text)
        off = m.disabled_profiles()
        self.warning.configure(text=(
            'Внимание: брандмауэр Windows выключен для профилей сети: %s. Пока он выключен, '
            'запреты не действуют.' % ', '.join(off)) if off else '')

    def _fill(self):
        rows = []
        self._entries = {}
        for e in sorted(self.manager.entries, key=lambda e: (entry_title(e).lower(), e.service.lower())):
            iid = 'f' + '|'.join(e.key)
            self._entries[iid] = e
            if e.enabled is True:
                state, tags = 'запрещено', ()
            elif e.enabled is False:
                state, tags = 'временно разрешено', ('paused',)
            else:
                state, tags = 'частично разрешено', ('paused',)
            rows.append((iid, (entry_title(e), e.service, directions_label(e.directions), state,
                               e.program), tags))
        self.app._sync_tree(self.tree, self._cache, rows)
        self._update_buttons()

    def _selected(self):
        return [self._entries[i] for i in self.tree.selection() if i in self._entries]

    def _update_buttons(self):
        selected = self._selected()
        self.btn_remove.state(['!disabled'] if selected else ['disabled'])
        self.btn_pause.state(['!disabled'] if any(e.enabled is not False for e in selected)
                             else ['disabled'])
        self.btn_resume.state(['!disabled'] if any(e.enabled is not True for e in selected)
                              else ['disabled'])

    def _menu(self, event):
        iid = self.tree.identify_row(event.y)
        if not iid:
            return
        if iid not in self.tree.selection():
            self.tree.selection_set(iid)
        menu = tk.Menu(self.tree, tearoff=False)
        menu.add_command(label='Убрать из списка (разрешить)', command=self.remove)
        menu.add_command(label='Временно разрешить', command=lambda: self.set_enabled(False))
        menu.add_command(label='Снова запретить', command=lambda: self.set_enabled(True))
        menu.tk_popup(event.x_root, event.y_root)

    # ------------------------------------------------------------ действия

    def add(self, initial=None):
        BlockDialog(self.app.root, self.manager, self.app.block_candidates(), initial,
                    on_submit=self.app.watch_firewall)

    def remove(self):
        selected = self._selected()
        if not selected:
            return
        names = '\n'.join('• ' + entry_title(e) + (' (служба %s)' % e.service if e.service else '')
                          for e in selected)
        if messagebox.askyesno('Разрешить доступ в сеть',
                               'Убрать из списка и снова разрешить доступ в сеть?\n\n%s' % names,
                               parent=self.app.root):
            self.manager.unblock(selected)
            self.app.watch_firewall()

    def set_enabled(self, enabled):
        selected = [e for e in self._selected() if e.enabled is not enabled]
        if selected:
            self.manager.set_enabled(selected, enabled)
            self.app.watch_firewall()


class BlockDialog(tk.Toplevel):
    """Окно выбора программы и параметров запрета."""

    def __init__(self, parent, manager, candidates, initial=None, on_submit=None):
        super().__init__(parent)
        self.manager = manager
        self.candidates = candidates      # [(подпись, путь, службы, pid)]
        self.on_submit = on_submit
        self._last_choice = None
        self.title('Запретить программе доступ в сеть')
        self.transient(parent)
        self.resizable(True, False)

        body = ttk.Frame(self, padding=14)
        body.pack(fill='both', expand=True)
        body.columnconfigure(0, weight=1)
        ttk.Label(body, text='Программа — выберите из тех, что работали с сетью, или укажите файл .exe:'
                  ).grid(row=0, column=0, columnspan=2, sticky='w')
        self.var_program = tk.StringVar()
        self.combo = ttk.Combobox(body, textvariable=self.var_program, width=90,
                                  values=[c[0] for c in candidates])
        self.combo.grid(row=1, column=0, sticky='ew', pady=(4, 0))
        ttk.Button(body, text='Обзор…', command=self._browse).grid(row=1, column=1, padx=(6, 0),
                                                                   pady=(4, 0))
        self.path_label = ttk.Label(body, text='', foreground='#555555')
        self.path_label.grid(row=2, column=0, columnspan=2, sticky='w', pady=(2, 0))

        self.svc_frame = ttk.Frame(body)
        self.svc_frame.grid(row=3, column=0, columnspan=2, sticky='ew', pady=(8, 0))
        self.svc_frame.columnconfigure(1, weight=1)
        ttk.Label(self.svc_frame, text='svchost.exe — общий процесс для служб Windows, поэтому запрет '
                  'ставится на отдельные службы.').grid(row=0, column=0, columnspan=2, sticky='w')
        ttk.Label(self.svc_frame, text='Службы (через запятую):').grid(row=1, column=0, sticky='w')
        self.var_services = tk.StringVar()
        ttk.Entry(self.svc_frame, textvariable=self.var_services).grid(row=1, column=1, sticky='ew',
                                                                       padx=(6, 0))

        ttk.Label(body, text='Что запретить:').grid(row=4, column=0, sticky='w', pady=(10, 0))
        self.var_dir = tk.StringVar(value='both')
        ttk.Radiobutton(body, text='Всё: и исходящие, и входящие соединения', value='both',
                        variable=self.var_dir).grid(row=5, column=0, sticky='w')
        ttk.Radiobutton(body, text='Только исходящие: программа не сможет ничего отправить сама',
                        value='out', variable=self.var_dir).grid(row=6, column=0, sticky='w')

        self.warn = ttk.Label(body, text='', foreground='#b00020', justify='left', wraplength=640)
        self.warn.grid(row=7, column=0, columnspan=2, sticky='w', pady=(10, 0))

        buttons = ttk.Frame(body)
        buttons.grid(row=8, column=0, columnspan=2, sticky='e', pady=(12, 0))
        self.ok = ttk.Button(buttons, text='Запретить', command=self._submit)
        self.ok.pack(side='left')
        ttk.Button(buttons, text='Отмена', command=self.destroy).pack(side='left', padx=(6, 0))

        self.var_program.trace_add('write', lambda *a: self._changed())
        self.var_services.trace_add('write', lambda *a: self._changed())
        self.bind('<Return>', lambda e: self._submit())
        self.bind('<Escape>', lambda e: self.destroy())

        if initial:
            label = next((c[0] for c in candidates if c[1] == initial[0] and c[2] == initial[1]), None)
            self.var_program.set(label or initial[0])
            self.var_services.set(initial[1] or '')
        self._changed()
        self._place(parent)
        self.grab_set()
        self.combo.focus_set()

    def _place(self, parent):
        self.update_idletasks()
        x = parent.winfo_rootx() + max(0, (parent.winfo_width() - self.winfo_reqwidth()) // 2)
        y = parent.winfo_rooty() + max(0, (parent.winfo_height() - self.winfo_reqheight()) // 3)
        self.geometry('+%d+%d' % (x, y))

    def _resolve(self):
        text = self.var_program.get().strip()
        for label, path, services, pid in self.candidates:
            if text == label:
                return path, services, pid, label
        return text.strip('"'), None, None, None

    def _browse(self):
        path = filedialog.askopenfilename(parent=self, title='Выберите программу',
                                          filetypes=[('Программы', '*.exe'), ('Все файлы', '*.*')])
        if path:
            self.var_program.set(path.replace('/', '\\'))

    def _is_svchost(self, path):
        return ntpath.basename(path).lower() == 'svchost.exe'

    def _changed(self):
        path, services, pid, label = self._resolve()
        if label is not None and label != self._last_choice:
            self.var_services.set(services or '')   # новая программа из списка — её службы
        self._last_choice = label
        self.path_label.configure(text=path if label else '')
        if self._is_svchost(path):
            self.svc_frame.grid()
        else:
            self.svc_frame.grid_remove()
        error = check_blockable(path, self._services(path), pid)
        notes = [] if error else warnings_for(path, self._services(path))
        self.warn.configure(text=error or '\n'.join('⚠ ' + n for n in notes))
        self.ok.state(['disabled'] if error else ['!disabled'])

    def _services(self, path):
        return split_services(self.var_services.get()) if self._is_svchost(path) else []

    def _submit(self):
        path, _services, pid, _label = self._resolve()
        services = self._services(path)
        error = check_blockable(path, services, pid)
        if error:
            messagebox.showerror('Нельзя запретить', error, parent=self)
            return
        directions = ('out', 'in') if self.var_dir.get() == 'both' else ('out',)
        self.manager.block(path, services, directions)
        if self.on_submit:
            self.on_submit()
        self.destroy()
