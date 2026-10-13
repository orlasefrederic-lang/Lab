# -*- coding: utf-8 -*-
"""
Буфер обмена Windows: просмотр и очистка.

Что умеет:
  * показывает, что сейчас лежит в буфере обмена (текст, файлы, картинка);
  * показывает журнал буфера обмена Windows (тот, что открывается по Win+V);
  * очищает буфер, удаляет отдельные записи журнала или весь журнал;
  * может сам стирать скопированное через N секунд (удобно для паролей).

Нужен только Python 3 для Windows 10/11, сторонние пакеты не нужны.
Запуск:  python clipboard_manager.py
Чтобы при двойном клике не открывалось чёрное окно консоли,
переименуйте файл в clipboard_manager.pyw.
"""

import base64
import ctypes
import json
import os
import queue
import subprocess
import sys
import threading
import time
from contextlib import contextmanager

if sys.platform != "win32":
    sys.exit("Эта программа работает только в Windows.")

import tkinter as tk
import winreg
from ctypes import wintypes
from tkinter import font as tkfont
from tkinter import ttk


# --------------------------------------------------------------------------
# Текущий буфер обмена (Win32 API через ctypes)
# --------------------------------------------------------------------------

CF_BITMAP = 2
CF_DIB = 8
CF_UNICODETEXT = 13
CF_HDROP = 15
CF_DIBV5 = 17
IMAGE_FORMATS = (CF_BITMAP, CF_DIB, CF_DIBV5)
STANDARD_FORMATS = {
    1: "CF_TEXT", 2: "CF_BITMAP", 3: "CF_METAFILEPICT", 7: "CF_OEMTEXT",
    8: "CF_DIB", 13: "CF_UNICODETEXT", 14: "CF_ENHMETAFILE", 15: "CF_HDROP",
    16: "CF_LOCALE", 17: "CF_DIBV5",
}

user32 = ctypes.WinDLL("user32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
shell32 = ctypes.WinDLL("shell32", use_last_error=True)


def _api(func, restype, *argtypes):
    # Без явных типов 64-битный Python обрезает указатели до 32 бит и падает.
    func.restype = restype
    func.argtypes = argtypes
    return func


OpenClipboard = _api(user32.OpenClipboard, wintypes.BOOL, wintypes.HWND)
CloseClipboard = _api(user32.CloseClipboard, wintypes.BOOL)
EmptyClipboard = _api(user32.EmptyClipboard, wintypes.BOOL)
GetClipboardData = _api(user32.GetClipboardData, wintypes.HANDLE, wintypes.UINT)
EnumClipboardFormats = _api(user32.EnumClipboardFormats, wintypes.UINT, wintypes.UINT)
IsClipboardFormatAvailable = _api(user32.IsClipboardFormatAvailable, wintypes.BOOL, wintypes.UINT)
GetClipboardSequenceNumber = _api(user32.GetClipboardSequenceNumber, wintypes.DWORD)
GetClipboardFormatNameW = _api(user32.GetClipboardFormatNameW, ctypes.c_int,
                               wintypes.UINT, wintypes.LPWSTR, ctypes.c_int)
GlobalLock = _api(kernel32.GlobalLock, wintypes.LPVOID, wintypes.HGLOBAL)
GlobalUnlock = _api(kernel32.GlobalUnlock, wintypes.BOOL, wintypes.HGLOBAL)
GlobalSize = _api(kernel32.GlobalSize, ctypes.c_size_t, wintypes.HGLOBAL)
DragQueryFileW = _api(shell32.DragQueryFileW, wintypes.UINT,
                      wintypes.HANDLE, wintypes.UINT, wintypes.LPWSTR, wintypes.UINT)


class ClipboardBusy(Exception):
    pass


class ClipContent:
    def __init__(self, kind, text=None, files=None, formats=()):
        self.kind = kind          # empty | text | files | image | other
        self.text = text
        self.files = files or []
        self.formats = list(formats)


@contextmanager
def _open_clipboard():
    # Буфер может на мгновение держать другая программа, поэтому пробуем несколько раз.
    for _ in range(10):
        if OpenClipboard(None):
            break
        time.sleep(0.03)
    else:
        raise ClipboardBusy("буфер обмена занят другой программой")
    try:
        yield
    finally:
        CloseClipboard()


def _read_text():
    handle = GetClipboardData(CF_UNICODETEXT)
    if not handle:
        return None
    ptr = GlobalLock(handle)
    if not ptr:
        return None
    try:
        raw = ctypes.wstring_at(ptr, GlobalSize(handle) // 2)
    finally:
        GlobalUnlock(handle)
    return raw.split("\0", 1)[0]


def _read_files():
    handle = GetClipboardData(CF_HDROP)
    if not handle:
        return []
    files = []
    for i in range(DragQueryFileW(handle, 0xFFFFFFFF, None, 0)):
        length = DragQueryFileW(handle, i, None, 0)
        buf = ctypes.create_unicode_buffer(length + 1)
        DragQueryFileW(handle, i, buf, length + 1)
        files.append(buf.value)
    return files


def format_name(fmt):
    if fmt in STANDARD_FORMATS:
        return STANDARD_FORMATS[fmt]
    buf = ctypes.create_unicode_buffer(256)
    if GetClipboardFormatNameW(fmt, buf, len(buf)):
        return buf.value
    return "#%d" % fmt


def read_clipboard():
    with _open_clipboard():
        formats = []
        fmt = EnumClipboardFormats(0)
        while fmt:
            formats.append(fmt)
            fmt = EnumClipboardFormats(fmt)
        if not formats:
            return ClipContent("empty")
        if CF_HDROP in formats:
            return ClipContent("files", files=_read_files(), formats=formats)
        if IsClipboardFormatAvailable(CF_UNICODETEXT):
            text = _read_text()
            if text is not None:
                return ClipContent("text", text=text, formats=formats)
        if any(f in formats for f in IMAGE_FORMATS):
            return ClipContent("image", formats=formats)
        return ClipContent("other", formats=formats)


def clear_clipboard():
    with _open_clipboard():
        if not EmptyClipboard():
            raise ctypes.WinError(ctypes.get_last_error())


def cloud_sync_enabled():
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Clipboard") as key:
            return winreg.QueryValueEx(key, "EnableCloudClipboard")[0] == 1
    except OSError:
        return False


# --------------------------------------------------------------------------
# Журнал буфера обмена (Win+V)
# --------------------------------------------------------------------------
# У журнала нет Win32 API, только WinRT. Из «голого» Python до WinRT не
# дотянуться без сторонних пакетов, поэтому вызываем встроенный в Windows
# PowerShell 5.1: он умеет работать с WinRT из коробки.

PS_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
function Out-Json($obj) {
    # Only ASCII on stdout (\uXXXX escapes), so the console code page does not matter.
    $json = ConvertTo-Json -InputObject $obj -Depth 5 -Compress
    $json = [regex]::Replace($json, '[^\x00-\x7F]', { param($m) '\u{0:x4}' -f [int][char]$m.Value })
    [Console]::Out.Write($json)
}
try {
    Add-Type -AssemblyName System.Runtime.WindowsRuntime
    $null = [Windows.ApplicationModel.DataTransfer.Clipboard, Windows.ApplicationModel.DataTransfer, ContentType = WindowsRuntime]
    $null = [Windows.ApplicationModel.DataTransfer.ClipboardHistoryItemsResult, Windows.ApplicationModel.DataTransfer, ContentType = WindowsRuntime]
    $null = [Windows.ApplicationModel.DataTransfer.StandardDataFormats, Windows.ApplicationModel.DataTransfer, ContentType = WindowsRuntime]
    $asTask = [System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
        $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and
        $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1'
    } | Select-Object -First 1
    function Await($op, [Type]$type) {
        $task = $asTask.MakeGenericMethod($type).Invoke($null, @($op))
        $null = $task.Wait(-1)
        $task.Result
    }
    $Clip = [Windows.ApplicationModel.DataTransfer.Clipboard]
    $Fmt = [Windows.ApplicationModel.DataTransfer.StandardDataFormats]
    function Get-ItemText($item) {
        try {
            if ($item.Content.Contains($Fmt::Text)) { return Await ($item.Content.GetTextAsync()) ([string]) }
        } catch { }
        return $null
    }

    $action = $env:CLIP_ACTION
    if ($action -eq 'clear') {
        Out-Json @{ ok = $true; cleared = $Clip::ClearHistory() }
        return
    }
    if (-not $Clip::IsHistoryEnabled()) {
        Out-Json @{ ok = $true; status = 'ClipboardHistoryDisabled'; items = @() }
        return
    }
    $res = Await ($Clip::GetHistoryItemsAsync()) ([Windows.ApplicationModel.DataTransfer.ClipboardHistoryItemsResult])
    $status = $res.Status.ToString()
    if ($status -ne 'Success') {
        Out-Json @{ ok = $true; status = $status; items = @() }
        return
    }
    $items = @($res.Items)

    if ($action -eq 'list') {
        $out = New-Object System.Collections.ArrayList
        foreach ($it in $items) {
            $c = $it.Content
            $text = Get-ItemText $it
            if ($text -ne $null) { $kind = 'text' }
            elseif ($c.Contains($Fmt::Bitmap)) { $kind = 'image' }
            elseif ($c.Contains($Fmt::StorageItems)) { $kind = 'files' }
            elseif ($c.Contains($Fmt::Html)) { $kind = 'html' }
            else { $kind = 'other' }
            $null = $out.Add([ordered]@{
                id = $it.Id
                time = $it.Timestamp.LocalDateTime.ToString('dd.MM.yyyy HH:mm:ss')
                kind = $kind
                text = $text
            })
        }
        Out-Json @{ ok = $true; status = $status; items = $out }
    }
    elseif ($action -eq 'delete_ids' -or $action -eq 'delete_text') {
        $ids = @($env:CLIP_IDS -split "`n")
        $deleted = 0
        foreach ($it in $items) {
            if ($action -eq 'delete_ids') { $match = $ids -ccontains $it.Id }
            else { $match = (Get-ItemText $it) -ceq $env:CLIP_TEXT }
            if ($match -and $Clip::DeleteItemFromHistory($it)) { $deleted++ }
        }
        Out-Json @{ ok = $true; status = $status; deleted = $deleted }
    }
    else { throw "unknown action: $action" }
}
catch {
    $e = $_.Exception
    while ($e.InnerException) { $e = $e.InnerException }
    Out-Json @{ ok = $false; error = $e.Message }
}
"""

HISTORY_STATUS_TEXT = {
    "ClipboardHistoryDisabled": "Журнал буфера выключен. Включить: Параметры → Система → Буфер обмена.",
    "AccessDenied": "Windows не дала доступ к журналу буфера обмена.",
}


class HistoryError(Exception):
    pass


def _powershell_exe():
    path = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                        "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
    return path if os.path.exists(path) else "powershell.exe"


def history_call(action, **params):
    # Параметры (в том числе текст пароля) передаём через переменные окружения
    # дочернего процесса, а не через командную строку, которую видят другие программы.
    env = dict(os.environ, CLIP_ACTION=action)
    for name, value in params.items():
        env["CLIP_" + name.upper()] = value
    encoded = base64.b64encode(PS_SCRIPT.encode("utf-16-le")).decode("ascii")
    try:
        proc = subprocess.run(
            [_powershell_exe(), "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
            env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=60,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise HistoryError("не удалось запустить PowerShell: %s" % exc)
    out = proc.stdout.decode("ascii", "replace")
    start = out.find("{")
    if start < 0:
        err = proc.stderr.decode("oem", "replace").strip()
        raise HistoryError(err[:300] or "PowerShell ничего не ответил")
    data = json.JSONDecoder().raw_decode(out, start)[0]
    if not data.get("ok"):
        raise HistoryError(data.get("error") or "неизвестная ошибка")
    return data


# --------------------------------------------------------------------------
# Окно программы
# --------------------------------------------------------------------------

KIND_NAMES = {"text": "Текст", "image": "Картинка", "files": "Файлы",
              "html": "HTML", "other": "Другое"}
MASK = "\u2022"


def masked(text):
    return MASK * min(len(text), 40) if text else ""


def one_line(text, limit=90):
    line = " ".join(text.split())
    return line if len(line) <= limit else line[:limit - 1] + "…"


class App:
    POLL_MS = 300
    HISTORY_DELAY = 1.0  # сек: даём Windows время дописать новую запись в журнал

    def __init__(self, root):
        self.root = root
        self.show_var = tk.BooleanVar(value=False)
        self.auto_var = tk.BooleanVar(value=False)
        self.auto_sec_var = tk.StringVar(value="30")
        self.auto_hist_var = tk.BooleanVar(value=True)

        self.last_seq = None
        self.current = ClipContent("empty")
        self.clear_at = None
        self.history = []
        self.history_refresh_at = time.monotonic()

        self.tasks = queue.Queue()
        self.results = queue.Queue()
        self.pending = 0
        threading.Thread(target=self._worker, daemon=True).start()

        self._build_ui()
        self._poll()

    # ---------- интерфейс ----------

    def _build_ui(self):
        root = self.root
        root.title("Буфер обмена")
        pad = {"padx": 8, "pady": 4}
        # Размеры считаем от шрифта, чтобы ничего не обрезалось при масштабе 125–150%.
        base = tkfont.nametofont("TkDefaultFont")
        ttk.Style(root).configure("Treeview", rowheight=base.metrics("linespace") + 6)

        cur = ttk.LabelFrame(root, text="Сейчас в буфере обмена")
        cur.pack(fill="x", **pad)

        self.cur_status = ttk.Label(cur, text="…", font=("Segoe UI", 10, "bold"))
        self.cur_status.pack(anchor="w", padx=8, pady=(6, 2))

        self.cur_text = tk.Text(cur, height=6, wrap="word", font=("Consolas", 11),
                                state="disabled", relief="solid", borderwidth=1)
        self.cur_text.pack(fill="x", padx=8, pady=2)

        row = ttk.Frame(cur)
        row.pack(fill="x", padx=8, pady=(2, 4))
        ttk.Checkbutton(row, text="Показывать содержимое", variable=self.show_var,
                        command=self._render_all).pack(side="left")
        ttk.Button(row, text="Очистить буфер", command=self.on_clear_clipboard).pack(side="right")

        row = ttk.Frame(cur)
        row.pack(fill="x", padx=8, pady=(0, 2))
        ttk.Checkbutton(row, text="Автоочистка через", variable=self.auto_var,
                        command=self._on_auto_toggle).pack(side="left")
        ttk.Spinbox(row, from_=5, to=600, increment=5, width=5,
                    textvariable=self.auto_sec_var).pack(side="left", padx=4)
        ttk.Label(row, text="сек после копирования").pack(side="left")
        self.countdown = ttk.Label(row, text="", foreground="#b35c00")
        self.countdown.pack(side="right")

        ttk.Checkbutton(cur, text="…и удалять этот текст из журнала Win+V",
                        variable=self.auto_hist_var).pack(anchor="w", padx=28, pady=(0, 6))

        hist = ttk.LabelFrame(root, text="Журнал буфера обмена Windows (Win+V)")
        hist.pack(fill="both", expand=True, **pad)

        table = ttk.Frame(hist)
        table.pack(fill="both", expand=True, padx=8, pady=(6, 2))
        self.tree = ttk.Treeview(table, columns=("time", "kind", "content"), height=10,
                                 show="headings", selectmode="extended")
        self.tree.heading("time", text="Когда")
        self.tree.heading("kind", text="Тип")
        self.tree.heading("content", text="Содержимое")
        self.tree.column("time", width=base.measure("00.00.0000 00:00:00") + 16, stretch=False)
        self.tree.column("kind", width=base.measure("Картинка") + 16, stretch=False)
        self.tree.column("content", width=base.measure("0") * 50)
        scroll = ttk.Scrollbar(table, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.tree.bind("<Delete>", lambda e: self.on_delete_selected())

        row = ttk.Frame(hist)
        row.pack(fill="x", padx=8, pady=(2, 2))
        self.hist_buttons = [
            ttk.Button(row, text="Обновить", command=self.refresh_history),
            ttk.Button(row, text="Удалить выбранное", command=self.on_delete_selected),
            ttk.Button(row, text="Очистить журнал", command=self.on_clear_history),
        ]
        for b in self.hist_buttons:
            b.pack(side="left", padx=(0, 6))
        self.hist_status = ttk.Label(hist, text="", wraplength=base.measure("0") * 80)
        self.hist_status.pack(anchor="w", padx=8, pady=(0, 6))

        if cloud_sync_enabled():
            ttk.Label(root, foreground="#c00000", wraplength=base.measure("0") * 80,
                      text="Включена синхронизация буфера между устройствами: скопированное "
                           "может уходить в облако Microsoft. Проверьте: Параметры → Система → "
                           "Буфер обмена.").pack(anchor="w", **pad)
        ttk.Button(root, text="Очистить всё (буфер + журнал)",
                   command=self.on_clear_all).pack(anchor="e", padx=8, pady=(0, 8))

        root.update_idletasks()
        root.minsize(root.winfo_reqwidth(), root.winfo_reqheight())

    def _set_text(self, value):
        self.cur_text.configure(state="normal")
        self.cur_text.delete("1.0", "end")
        self.cur_text.insert("1.0", value)
        self.cur_text.configure(state="disabled")

    def _render_current(self):
        c = self.current
        if c.kind == "empty":
            self.cur_status.configure(text="Пусто")
            self._set_text("")
        elif c.kind == "text":
            self.cur_status.configure(text="Текст, символов: %d" % len(c.text))
            self._set_text(c.text if self.show_var.get() else masked(c.text))
        elif c.kind == "files":
            self.cur_status.configure(text="Файлы, штук: %d" % len(c.files))
            self._set_text("\n".join(c.files))
        elif c.kind == "image":
            self.cur_status.configure(text="Картинка")
            self._set_text("")
        else:
            self.cur_status.configure(text="Другие данные")
            self._set_text("Форматы: " + ", ".join(format_name(f) for f in c.formats))

    def _render_history(self):
        self.tree.delete(*self.tree.get_children())
        show = self.show_var.get()
        for i, item in enumerate(self.history):
            text = item.get("text")
            if text is None:
                content = ""
            elif show:
                content = one_line(text)
            else:
                content = "%s  (%d симв.)" % (masked(text), len(text))
            self.tree.insert("", "end", iid=str(i), values=(
                item.get("time", ""), KIND_NAMES.get(item.get("kind"), "Другое"), content))

    def _render_all(self):
        self._render_current()
        self._render_history()

    # ---------- фоновые задачи (PowerShell работает секунду-другую) ----------

    def _worker(self):
        while True:
            func, args, kwargs, done = self.tasks.get()
            try:
                result, error = func(*args, **kwargs), None
            except Exception as exc:  # noqa: BLE001 - показываем любую ошибку в окне
                result, error = None, exc
            self.results.put((done, result, error))

    def _submit(self, done, func, *args, **kwargs):
        self.pending += 1
        self.tasks.put((func, args, kwargs, done))
        self._update_busy()

    def _update_busy(self):
        state = "disabled" if self.pending else "normal"
        for b in self.hist_buttons:
            b.configure(state=state)
        if self.pending:
            self.hist_status.configure(text="Работаю…", foreground="")

    def _show_history_error(self, error):
        self.hist_status.configure(text="Ошибка: %s" % error, foreground="#c00000")

    def refresh_history(self):
        self.history_refresh_at = None
        self._submit(self._on_history_loaded, history_call, "list")

    def _on_history_loaded(self, data, error):
        if error:
            self._show_history_error(error)
            return
        status = data.get("status")
        self.history = data.get("items") or []
        self._render_history()
        if status != "Success":
            self.hist_status.configure(text=HISTORY_STATUS_TEXT.get(status, status),
                                       foreground="#c00000")
        else:
            self.hist_status.configure(text="Записей: %d" % len(self.history), foreground="")

    def _after_history_change(self, data, error):
        if error:
            self._show_history_error(error)
        else:
            self.refresh_history()

    # ---------- кнопки ----------

    def on_clear_clipboard(self):
        try:
            clear_clipboard()
            return True
        except Exception as exc:  # noqa: BLE001
            self.cur_status.configure(text="Не получилось очистить: %s" % exc)
            return False

    def on_delete_selected(self):
        ids = [self.history[int(iid)].get("id") or "" for iid in self.tree.selection()]
        if ids:
            self._submit(self._after_history_change, history_call, "delete_ids", ids="\n".join(ids))

    def on_clear_history(self):
        self._submit(self._after_history_change, history_call, "clear")

    def on_clear_all(self):
        self.on_clear_clipboard()
        self.on_clear_history()

    def _on_auto_toggle(self):
        self.clear_at = None
        self._arm_auto_clear()

    def _auto_seconds(self):
        try:
            return max(1, int(self.auto_sec_var.get()))
        except ValueError:
            return 30

    def _arm_auto_clear(self):
        if self.auto_var.get() and self.current.kind != "empty":
            self.clear_at = time.monotonic() + self._auto_seconds()
        else:
            self.clear_at = None
            self.countdown.configure(text="")

    def _do_auto_clear(self):
        text = self.current.text if self.current.kind == "text" else None
        if not self.on_clear_clipboard():
            self.clear_at = time.monotonic() + 1  # буфер занят — повторим через секунду
            return
        self.clear_at = None
        self.countdown.configure(text="")
        # Огромный текст в переменную окружения не влезет, а пароли короткие.
        if text and len(text) <= 10000 and self.auto_hist_var.get():
            self._submit(self._after_history_change, history_call, "delete_text", text=text)

    # ---------- главный цикл ----------

    def _poll(self):
        try:
            self._tick()
        finally:
            # Цикл не должен остановиться, даже если на одном круге что-то упало.
            self.root.after(self.POLL_MS, self._poll)

    def _tick(self):
        now = time.monotonic()

        seq = GetClipboardSequenceNumber()
        if seq != self.last_seq:
            try:
                self.current = read_clipboard()
            except ClipboardBusy:
                pass  # попробуем на следующем круге
            else:
                self.last_seq = seq
                self._render_current()
                self._arm_auto_clear()
                self.history_refresh_at = now + self.HISTORY_DELAY

        if self.clear_at is not None:
            left = self.clear_at - now
            if left <= 0:
                self._do_auto_clear()
            else:
                self.countdown.configure(text="Сотру через %d сек" % (int(left) + 1))

        while not self.results.empty():
            done, result, error = self.results.get()
            self.pending -= 1
            self._update_busy()
            if done:
                done(result, error)

        if self.history_refresh_at is not None and now >= self.history_refresh_at and not self.pending:
            self.refresh_history()


def main():
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)  # чёткий шрифт на экранах с масштабом
    except (AttributeError, OSError):
        pass
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
