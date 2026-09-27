"""Обёртки над Win32 API через ctypes: процессы, службы, TCP-соединения.

Сторонние библиотеки не нужны. На других ОС модуль импортируется (для тестов),
но системные функции там недоступны.
"""

import ctypes
import logging
import os
import socket
import string
import struct
import subprocess
import sys
import threading
import time
from ctypes import POINTER, Structure, byref, sizeof

from util import ip_from_bytes, normalize_ip

log = logging.getLogger('netmon.winapi')

IS_WINDOWS = sys.platform == 'win32'

# Типы фиксированного размера (как в Windows): раскладка структур не зависит
# от платформы, на которой её проверяют тесты.
UCHAR = BYTE = ctypes.c_uint8
USHORT = WORD = ctypes.c_uint16
ULONG = DWORD = ctypes.c_uint32
LONG = ctypes.c_int32
BOOL = ctypes.c_int32
ULONG64 = ULONGLONG = ctypes.c_uint64
LONGLONG = ctypes.c_int64
HANDLE = ctypes.c_void_p
WCHAR = ctypes.c_uint16


class GUID(Structure):
    _fields_ = [('Data1', DWORD), ('Data2', WORD), ('Data3', WORD), ('Data4', BYTE * 8)]

    @classmethod
    def from_uuid(cls, value):
        return cls.from_buffer_copy(value.bytes_le)


class FILETIME(Structure):
    _fields_ = [('dwLowDateTime', DWORD), ('dwHighDateTime', DWORD)]

    def to_int(self):
        return (self.dwHighDateTime << 32) | self.dwLowDateTime


FILETIME_UNIX_EPOCH = 116444736000000000  # 1970-01-01 в единицах FILETIME (100 нс)


def filetime_to_unix(value):
    if not value:
        return None
    return (value - FILETIME_UNIX_EPOCH) / 1e7


PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
TH32CS_SNAPPROCESS = 0x00000002
ERROR_ACCESS_DENIED = 5
ERROR_INVALID_PARAMETER = 87
ERROR_INSUFFICIENT_BUFFER = 122
ERROR_ALREADY_EXISTS = 183
ERROR_MORE_DATA = 234
SC_MANAGER_ENUMERATE_SERVICE = 0x0004
SC_ENUM_PROCESS_INFO = 0
SERVICE_WIN32 = 0x00000030
SERVICE_ACTIVE = 0x00000001
TCP_TABLE_OWNER_PID_ALL = 5
WIN_AF_INET = 2
WIN_AF_INET6 = 23
PROCESS_COMMAND_LINE_INFORMATION = 60
MAX_PATH = 260
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class PROCESSENTRY32W(Structure):
    _fields_ = [('dwSize', DWORD), ('cntUsage', DWORD), ('th32ProcessID', DWORD),
                ('th32DefaultHeapID', ctypes.c_size_t), ('th32ModuleID', DWORD),
                ('cntThreads', DWORD), ('th32ParentProcessID', DWORD),
                ('pcPriClassBase', LONG), ('dwFlags', DWORD),
                ('szExeFile', ctypes.c_wchar * MAX_PATH)]


class SERVICE_STATUS_PROCESS(Structure):
    _fields_ = [(name, DWORD) for name in (
        'dwServiceType', 'dwCurrentState', 'dwControlsAccepted', 'dwWin32ExitCode',
        'dwServiceSpecificExitCode', 'dwCheckPoint', 'dwWaitHint', 'dwProcessId',
        'dwServiceFlags')]


class ENUM_SERVICE_STATUS_PROCESSW(Structure):
    _fields_ = [('lpServiceName', ctypes.c_wchar_p),
                ('lpDisplayName', ctypes.c_wchar_p),
                ('ServiceStatusProcess', SERVICE_STATUS_PROCESS)]


class UNICODE_STRING(Structure):
    _fields_ = [('Length', USHORT), ('MaximumLength', USHORT), ('Buffer', ctypes.c_void_p)]


def _proto(func, restype, *argtypes):
    func.restype = restype
    func.argtypes = argtypes
    return func


if IS_WINDOWS:
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)
    iphlpapi = ctypes.WinDLL('iphlpapi', use_last_error=True)
    shell32 = ctypes.WinDLL('shell32', use_last_error=True)
    ntdll = ctypes.WinDLL('ntdll')

    _OpenProcess = _proto(kernel32.OpenProcess, HANDLE, DWORD, BOOL, DWORD)
    _CloseHandle = _proto(kernel32.CloseHandle, BOOL, HANDLE)
    _QueryFullProcessImageNameW = _proto(kernel32.QueryFullProcessImageNameW, BOOL,
                                         HANDLE, DWORD, ctypes.c_wchar_p, POINTER(DWORD))
    _GetProcessTimes = _proto(kernel32.GetProcessTimes, BOOL, HANDLE, POINTER(FILETIME),
                              POINTER(FILETIME), POINTER(FILETIME), POINTER(FILETIME))
    _CreateToolhelp32Snapshot = _proto(kernel32.CreateToolhelp32Snapshot, HANDLE, DWORD, DWORD)
    _Process32FirstW = _proto(kernel32.Process32FirstW, BOOL, HANDLE, POINTER(PROCESSENTRY32W))
    _Process32NextW = _proto(kernel32.Process32NextW, BOOL, HANDLE, POINTER(PROCESSENTRY32W))
    _QueryDosDeviceW = _proto(kernel32.QueryDosDeviceW, DWORD,
                              ctypes.c_wchar_p, ctypes.c_wchar_p, DWORD)
    _CreateMutexW = _proto(kernel32.CreateMutexW, HANDLE, ctypes.c_void_p, BOOL, ctypes.c_wchar_p)
    _GetTickCount64 = _proto(kernel32.GetTickCount64, ctypes.c_uint64)
    _NtQueryInformationProcess = _proto(ntdll.NtQueryInformationProcess, LONG, HANDLE, ULONG,
                                        ctypes.c_void_p, ULONG, POINTER(ULONG))
    _OpenSCManagerW = _proto(advapi32.OpenSCManagerW, HANDLE,
                             ctypes.c_wchar_p, ctypes.c_wchar_p, DWORD)
    _EnumServicesStatusExW = _proto(advapi32.EnumServicesStatusExW, BOOL, HANDLE, ctypes.c_int,
                                    DWORD, DWORD, ctypes.c_void_p, DWORD, POINTER(DWORD),
                                    POINTER(DWORD), POINTER(DWORD), ctypes.c_wchar_p)
    _CloseServiceHandle = _proto(advapi32.CloseServiceHandle, BOOL, HANDLE)
    _GetExtendedTcpTable = _proto(iphlpapi.GetExtendedTcpTable, DWORD, ctypes.c_void_p,
                                  POINTER(DWORD), BOOL, ULONG, ctypes.c_int, ULONG)
    _ShellExecuteW = _proto(shell32.ShellExecuteW, HANDLE, HANDLE, ctypes.c_wchar_p,
                            ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_int)
    _IsUserAnAdmin = _proto(shell32.IsUserAnAdmin, BOOL)


# ------------------------------------------------------------ права и запуск

def is_admin():
    if not IS_WINDOWS:
        return hasattr(os, 'geteuid') and os.geteuid() == 0
    try:
        return bool(_IsUserAnAdmin())
    except OSError:
        return False


def relaunch_as_admin():
    """Перезапускает программу с запросом прав администратора (окно UAC).

    Возвращает True, если новый процесс запущен (текущий нужно завершить).
    """
    if getattr(sys, 'frozen', False):  # собранный .exe (PyInstaller)
        args = sys.argv[1:]
    else:
        args = [os.path.abspath(sys.argv[0])] + sys.argv[1:]
    workdir = os.path.dirname(os.path.abspath(sys.argv[0]))
    rc = _ShellExecuteW(None, 'runas', sys.executable, subprocess.list2cmdline(args), workdir, 1)
    return (rc or 0) > 32


_instance_mutex = None


def acquire_single_instance(name='Local\\NetActivityMonitor.SingleInstance'):
    """False, если программа уже запущена (два экземпляра мешали бы друг другу)."""
    global _instance_mutex
    if not IS_WINDOWS:
        return True
    handle = _CreateMutexW(None, False, name)
    err = ctypes.get_last_error()
    if not handle:
        return True
    if err == ERROR_ALREADY_EXISTS:
        _CloseHandle(handle)
        return False
    _instance_mutex = handle
    return True


def boot_time():
    return time.time() - _GetTickCount64() / 1000.0


# ------------------------------------------------------------------ процессы

def process_snapshot():
    """{pid: (имя exe, pid родителя)} для всех процессов."""
    result = {}
    snap = _CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if not snap or snap == INVALID_HANDLE_VALUE:
        return result
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = sizeof(PROCESSENTRY32W)
        ok = _Process32FirstW(snap, byref(entry))
        while ok:
            result[entry.th32ProcessID] = (entry.szExeFile, entry.th32ParentProcessID)
            ok = _Process32NextW(snap, byref(entry))
    finally:
        _CloseHandle(snap)
    return result


def _command_line(handle):
    need = ULONG(0)
    _NtQueryInformationProcess(handle, PROCESS_COMMAND_LINE_INFORMATION, None, 0, byref(need))
    size = need.value if 0 < need.value < (1 << 20) else 65536 + 64
    buf = ctypes.create_string_buffer(size)
    status = _NtQueryInformationProcess(handle, PROCESS_COMMAND_LINE_INFORMATION,
                                        buf, size, byref(need))
    if status < 0:
        return ''
    us = UNICODE_STRING.from_buffer(buf)
    if not us.Buffer or not us.Length:
        return ''
    return ctypes.wstring_at(us.Buffer, us.Length // 2)


def process_details(pid):
    """Путь, время запуска и командная строка процесса.

    None — процесса больше нет; {} — процесс есть, но доступ к нему закрыт.
    """
    system_root = os.environ.get('SystemRoot', r'C:\Windows')
    if pid == 0:
        return {'path': '', 'started': boot_time(), 'cmdline': ''}
    if pid == 4:
        return {'path': os.path.join(system_root, 'System32', 'ntoskrnl.exe'),
                'started': boot_time(), 'cmdline': ''}
    handle = _OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return None if ctypes.get_last_error() == ERROR_INVALID_PARAMETER else {}
    try:
        info = {}
        size = DWORD(32768)
        buf = ctypes.create_unicode_buffer(size.value)
        if _QueryFullProcessImageNameW(handle, 0, buf, byref(size)):
            info['path'] = buf.value
        created, exited, kernel, user = FILETIME(), FILETIME(), FILETIME(), FILETIME()
        if _GetProcessTimes(handle, byref(created), byref(exited), byref(kernel), byref(user)):
            info['started'] = filetime_to_unix(created.to_int())
            if exited.to_int():
                info['exited'] = filetime_to_unix(exited.to_int())
        try:
            info['cmdline'] = _command_line(handle)
        except OSError:
            pass
        return info
    finally:
        _CloseHandle(handle)


def services_by_pid():
    """{pid: [имена служб]} для работающих служб (кто живёт внутри svchost.exe)."""
    result = {}
    scm = _OpenSCManagerW(None, None, SC_MANAGER_ENUMERATE_SERVICE)
    if not scm:
        return result
    try:
        resume, needed, count = DWORD(0), DWORD(0), DWORD(0)
        bufsize = 64 * 1024
        for _ in range(32):
            buf = ctypes.create_string_buffer(bufsize)
            ok = _EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_ACTIVE,
                                        buf, bufsize, byref(needed), byref(count),
                                        byref(resume), None)
            err = ctypes.get_last_error()
            items = ctypes.cast(buf, POINTER(ENUM_SERVICE_STATUS_PROCESSW))
            for i in range(count.value):
                item = items[i]
                pid = item.ServiceStatusProcess.dwProcessId
                if pid and item.lpServiceName:
                    result.setdefault(pid, []).append(item.lpServiceName)
            if ok or err != ERROR_MORE_DATA:
                break
            bufsize = max(bufsize, min(needed.value + 1024, 256 * 1024))
    finally:
        _CloseServiceHandle(scm)
    return result


# ------------------------------------------------------------ TCP-соединения

def _tcp_table(family):
    size = DWORD(0)
    rc = _GetExtendedTcpTable(None, byref(size), False, family, TCP_TABLE_OWNER_PID_ALL, 0)
    for _ in range(5):
        if rc not in (0, ERROR_INSUFFICIENT_BUFFER):
            return None
        buf = ctypes.create_string_buffer(size.value + 16384)
        size = DWORD(len(buf))
        rc = _GetExtendedTcpTable(buf, byref(size), False, family, TCP_TABLE_OWNER_PID_ALL, 0)
        if rc == 0:
            return buf.raw
    return None


def parse_tcp_table_v4(raw):
    """MIB_TCPTABLE_OWNER_PID -> [(pid, state, lip, lport, rip, rport)]."""
    rows = []
    count = struct.unpack_from('<I', raw, 0)[0]
    for i in range(count):
        off = 4 + i * 24
        if off + 24 > len(raw):
            break
        state, = struct.unpack_from('<I', raw, off)
        pid, = struct.unpack_from('<I', raw, off + 20)
        rows.append((pid, state,
                     ip_from_bytes(raw[off + 4:off + 8]), int.from_bytes(raw[off + 8:off + 10], 'big'),
                     ip_from_bytes(raw[off + 12:off + 16]), int.from_bytes(raw[off + 16:off + 18], 'big')))
    return rows


def parse_tcp_table_v6(raw):
    """MIB_TCP6TABLE_OWNER_PID -> [(pid, state, lip, lport, rip, rport)]."""
    rows = []
    count = struct.unpack_from('<I', raw, 0)[0]
    for i in range(count):
        off = 4 + i * 56
        if off + 56 > len(raw):
            break
        state, pid = struct.unpack_from('<II', raw, off + 48)
        rows.append((pid, state,
                     ip_from_bytes(raw[off:off + 16]), int.from_bytes(raw[off + 20:off + 22], 'big'),
                     ip_from_bytes(raw[off + 24:off + 40]), int.from_bytes(raw[off + 44:off + 46], 'big')))
    return rows


def tcp_connections():
    rows = []
    raw = _tcp_table(WIN_AF_INET)
    if raw:
        rows.extend(parse_tcp_table_v4(raw))
    raw = _tcp_table(WIN_AF_INET6)
    if raw:
        rows.extend(parse_tcp_table_v6(raw))
    return rows


def local_addresses():
    addrs = {'127.0.0.1', '::1'}
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            ip = normalize_ip(info[4][0])
            if ip:
                addrs.add(ip)
    except OSError:
        pass
    return addrs


# ------------------------------------------- пути вида \Device\HarddiskVolume3\...

_device_lock = threading.Lock()
_device_map = []
_device_map_time = 0.0


def _load_device_map():
    result = []
    buf = ctypes.create_unicode_buffer(1024)
    for letter in string.ascii_uppercase:
        drive = letter + ':'
        if _QueryDosDeviceW(drive, buf, len(buf)):
            result.append((buf.value.lower(), drive))
    return result


def nt_path_to_dos(path):
    r"""'\Device\HarddiskVolume3\Windows\notepad.exe' -> 'C:\Windows\notepad.exe'."""
    global _device_map, _device_map_time
    if not path:
        return path
    if path.startswith('\\??\\'):
        return path[4:]
    low = path.lower()
    if low.startswith('\\systemroot\\'):
        return os.environ.get('SystemRoot', r'C:\Windows') + path[11:]
    if not low.startswith('\\device\\') or not IS_WINDOWS:
        return path
    for attempt in range(2):
        with _device_lock:
            if attempt or not _device_map:
                if attempt and time.time() - _device_map_time < 60:
                    break
                _device_map = _load_device_map()
                _device_map_time = time.time()
            mapping = _device_map
        for device, drive in mapping:
            if low.startswith(device + '\\'):
                return drive + path[len(device):]
    return path


class WinSysInfo:
    """Источник системной информации для Monitor (в демо-режиме — DemoSysInfo)."""

    def processes(self):
        return process_snapshot()

    def details(self, pid):
        return process_details(pid)

    def services(self):
        return services_by_pid()

    def tcp_connections(self):
        return tcp_connections()

    def local_addresses(self):
        return local_addresses()

    def nt_path_to_dos(self, path):
        return nt_path_to_dos(path)
