"""Приём событий ETW (Event Tracing for Windows) в реальном времени через ctypes.

Провайдеры:
  * Microsoft-Windows-Kernel-Network — каждая отправка/приём TCP и UDP:
    PID процесса-владельца сокета, адреса, порты и число байт;
  * Microsoft-Windows-Kernel-Process — запуск и завершение процессов
    (чтобы знать имена даже очень коротко живших программ);
  * Microsoft-Windows-DNS-Client — какие имена разрешались и в какие IP
    (чтобы показывать «api.github.com», а не голый адрес).

Нужны права администратора. Раскладка полей событий берётся из манифеста
провайдера через TDH (tdh.dll), поэтому код не зависит от версии Windows.
"""

import ctypes
import logging
import operator
import struct
import threading
import uuid
from collections import namedtuple
from ctypes import POINTER, Structure, byref, sizeof

from winapi import (GUID, HANDLE, IS_WINDOWS, LONG, LONGLONG, UCHAR, ULONG, ULONG64, USHORT,
                    WCHAR, FILETIME_UNIX_EPOCH)

log = logging.getLogger('netmon.etw')

KERNEL_NETWORK = uuid.UUID('7dd42a49-5329-4832-8dfd-43d979153a88')
KERNEL_PROCESS = uuid.UUID('22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716')
DNS_CLIENT = uuid.UUID('1c95126e-7eea-49a9-a3fe-a378b03ddb4d')
RT_LOST_EVENT = uuid.UUID('6a399ae0-4bc6-4de9-870b-3657f8947e7e')

SEND, RECV, ACCEPT = 1, 2, 3
# Microsoft-Windows-Kernel-Network: id события -> (протокол, что произошло)
NET_EVENTS = {
    10: ('TCP', SEND), 11: ('TCP', RECV), 15: ('TCP', ACCEPT),   # TCP/IPv4
    26: ('TCP', SEND), 27: ('TCP', RECV), 31: ('TCP', ACCEPT),   # TCP/IPv6
    42: ('UDP', SEND), 43: ('UDP', RECV),                        # UDP/IPv4
    58: ('UDP', SEND), 59: ('UDP', RECV),                        # UDP/IPv6
}
IPV6_EVENTS = frozenset({26, 27, 31, 58, 59})
PROCESS_START, PROCESS_STOP = 1, 2
DNS_EVENTS = (3008, 3020)   # «запрос выполнен» (в процессе-клиенте) и ответ сервера

# ------------------------------------------------------------------ структуры


class EVENT_DESCRIPTOR(Structure):
    _fields_ = [('Id', USHORT), ('Version', UCHAR), ('Channel', UCHAR), ('Level', UCHAR),
                ('Opcode', UCHAR), ('Task', USHORT), ('Keyword', ULONG64)]


class EVENT_HEADER(Structure):
    _fields_ = [('Size', USHORT), ('HeaderType', USHORT), ('Flags', USHORT),
                ('EventProperty', USHORT), ('ThreadId', ULONG), ('ProcessId', ULONG),
                ('TimeStamp', LONGLONG), ('ProviderId', GUID),
                ('EventDescriptor', EVENT_DESCRIPTOR), ('ProcessorTime', ULONG64),
                ('ActivityId', GUID)]


class ETW_BUFFER_CONTEXT(Structure):
    _fields_ = [('ProcessorIndex', USHORT), ('LoggerId', USHORT)]


class EVENT_RECORD(Structure):
    _fields_ = [('EventHeader', EVENT_HEADER), ('BufferContext', ETW_BUFFER_CONTEXT),
                ('ExtendedDataCount', USHORT), ('UserDataLength', USHORT),
                ('ExtendedData', ctypes.c_void_p), ('UserData', ctypes.c_void_p),
                ('UserContext', ctypes.c_void_p)]


class WNODE_HEADER(Structure):
    _fields_ = [('BufferSize', ULONG), ('ProviderId', ULONG), ('HistoricalContext', ULONG64),
                ('TimeStamp', LONGLONG), ('Guid', GUID), ('ClientContext', ULONG),
                ('Flags', ULONG)]


class EVENT_TRACE_PROPERTIES(Structure):
    _fields_ = [('Wnode', WNODE_HEADER), ('BufferSize', ULONG), ('MinimumBuffers', ULONG),
                ('MaximumBuffers', ULONG), ('MaximumFileSize', ULONG), ('LogFileMode', ULONG),
                ('FlushTimer', ULONG), ('EnableFlags', ULONG), ('AgeLimit', LONG),
                ('NumberOfBuffers', ULONG), ('FreeBuffers', ULONG), ('EventsLost', ULONG),
                ('BuffersWritten', ULONG), ('LogBuffersLost', ULONG),
                ('RealTimeBuffersLost', ULONG), ('LoggerThreadId', HANDLE),
                ('LogFileNameOffset', ULONG), ('LoggerNameOffset', ULONG)]


class EVENT_TRACE_HEADER(Structure):
    _fields_ = [('Size', USHORT), ('FieldTypeFlags', USHORT), ('Version', ULONG),
                ('ThreadId', ULONG), ('ProcessId', ULONG), ('TimeStamp', LONGLONG),
                ('Guid', GUID), ('ProcessorTime', ULONG64)]


class EVENT_TRACE(Structure):
    _fields_ = [('Header', EVENT_TRACE_HEADER), ('InstanceId', ULONG),
                ('ParentInstanceId', ULONG), ('ParentGuid', GUID),
                ('MofData', ctypes.c_void_p), ('MofLength', ULONG), ('ClientContext', ULONG)]


class SYSTEMTIME(Structure):
    _fields_ = [(name, USHORT) for name in ('wYear', 'wMonth', 'wDayOfWeek', 'wDay', 'wHour',
                                             'wMinute', 'wSecond', 'wMilliseconds')]


class TIME_ZONE_INFORMATION(Structure):
    _fields_ = [('Bias', LONG), ('StandardName', WCHAR * 32), ('StandardDate', SYSTEMTIME),
                ('StandardBias', LONG), ('DaylightName', WCHAR * 32),
                ('DaylightDate', SYSTEMTIME), ('DaylightBias', LONG)]


class TRACE_LOGFILE_HEADER(Structure):
    _fields_ = [('BufferSize', ULONG), ('Version', ULONG), ('ProviderVersion', ULONG),
                ('NumberOfProcessors', ULONG), ('EndTime', LONGLONG),
                ('TimerResolution', ULONG), ('MaximumFileSize', ULONG), ('LogFileMode', ULONG),
                ('BuffersWritten', ULONG), ('LogInstanceGuid', GUID),
                ('LoggerName', ctypes.c_void_p), ('LogFileName', ctypes.c_void_p),
                ('TimeZone', TIME_ZONE_INFORMATION), ('BootTime', LONGLONG),
                ('PerfFreq', LONGLONG), ('StartTime', LONGLONG), ('ReservedFlags', ULONG),
                ('BuffersLost', ULONG)]


class EVENT_TRACE_LOGFILEW(Structure):
    _fields_ = [('LogFileName', ctypes.c_wchar_p), ('LoggerName', ctypes.c_wchar_p),
                ('CurrentTime', LONGLONG), ('BuffersRead', ULONG), ('ProcessTraceMode', ULONG),
                ('CurrentEvent', EVENT_TRACE), ('LogfileHeader', TRACE_LOGFILE_HEADER),
                ('BufferCallback', ctypes.c_void_p), ('BufferSize', ULONG), ('Filled', ULONG),
                ('EventsLost', ULONG), ('EventRecordCallback', ctypes.c_void_p),
                ('IsKernelTrace', ULONG), ('Context', ctypes.c_void_p)]


class EVENT_FILTER_DESCRIPTOR(Structure):
    _fields_ = [('Ptr', ULONG64), ('Size', ULONG), ('Type', ULONG)]


class ENABLE_TRACE_PARAMETERS(Structure):
    _fields_ = [('Version', ULONG), ('EnableProperty', ULONG), ('ControlFlags', ULONG),
                ('SourceId', GUID), ('EnableFilterDesc', POINTER(EVENT_FILTER_DESCRIPTOR)),
                ('FilterDescCount', ULONG)]


class EVENT_PROPERTY_INFO(Structure):
    _fields_ = [('Flags', ULONG), ('NameOffset', ULONG), ('InType', USHORT),
                ('OutType', USHORT), ('MapNameOffset', ULONG), ('Count', USHORT),
                ('Length', USHORT), ('Reserved', ULONG)]


class TRACE_EVENT_INFO(Structure):
    # за структурой следует массив EVENT_PROPERTY_INFO[TopLevelPropertyCount]
    _fields_ = [('ProviderGuid', GUID), ('EventGuid', GUID),
                ('EventDescriptor', EVENT_DESCRIPTOR), ('DecodingSource', ULONG),
                ('ProviderNameOffset', ULONG), ('LevelNameOffset', ULONG),
                ('ChannelNameOffset', ULONG), ('KeywordsNameOffset', ULONG),
                ('TaskNameOffset', ULONG), ('OpcodeNameOffset', ULONG),
                ('EventMessageOffset', ULONG), ('ProviderMessageOffset', ULONG),
                ('BinaryXMLOffset', ULONG), ('BinaryXMLSize', ULONG),
                ('EventNameOffset', ULONG), ('EventAttributesOffset', ULONG),
                ('PropertyCount', ULONG), ('TopLevelPropertyCount', ULONG), ('Flags', ULONG)]


WNODE_FLAG_TRACED_GUID = 0x00020000
EVENT_TRACE_REAL_TIME_MODE = 0x00000100
EVENT_TRACE_CONTROL_QUERY = 0
EVENT_TRACE_CONTROL_STOP = 1
EVENT_CONTROL_CODE_ENABLE_PROVIDER = 1
PROCESS_TRACE_MODE_REAL_TIME = 0x00000100
PROCESS_TRACE_MODE_EVENT_RECORD = 0x10000000
EVENT_FILTER_TYPE_EVENT_ID = 0x80000200
ENABLE_TRACE_PARAMETERS_VERSION_2 = 2
EVENT_HEADER_FLAG_32_BIT_HEADER = 0x0020
TRACE_LEVEL_VERBOSE = 5
ALL_KEYWORDS = 0xFFFFFFFFFFFFFFFF
KERNEL_PROCESS_KEYWORD_PROCESS = 0x10

ERROR_ACCESS_DENIED = 5
ERROR_INSUFFICIENT_BUFFER = 122
ERROR_ALREADY_EXISTS = 183
ERROR_CANCELLED = 1223
ERROR_NO_SYSTEM_RESOURCES = 1450
ERROR_WMI_INSTANCE_NOT_FOUND = 4201
ERROR_CTX_CLOSE_PENDING = 7007
INVALID_PROCESSTRACE_HANDLE = (0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF)

# TDH: флаги свойств и типы данных
PROPERTY_STRUCT = 0x1
PROPERTY_PARAM_LENGTH = 0x2
PROPERTY_PARAM_COUNT = 0x4
TDH_INTYPE_UNICODESTRING = 1
TDH_INTYPE_ANSISTRING = 2
TDH_INTYPE_BINARY = 14
TDH_INTYPE_GUID = 15
TDH_INTYPE_POINTER = 16
TDH_INTYPE_SID = 19
TDH_INTYPE_COUNTEDSTRING = 300
TDH_INTYPE_COUNTEDANSISTRING = 301
TDH_INTYPE_SIZET = 308
TDH_INTYPE_WBEMSID = 310
TDH_OUTTYPE_IPV6 = 24

_FIXED_SIZES = {3: 1, 4: 1, 5: 2, 6: 2, 7: 4, 8: 4, 9: 8, 10: 8, 11: 4, 12: 8, 13: 4,
                15: 16, 17: 8, 18: 16, 20: 4, 21: 8, 306: 2, 307: 1}
_SIGNED_TYPES = frozenset({3, 5, 7, 9})
_FLOAT_FORMATS = {11: '<f', 12: '<d'}

# Смещения в EVENT_RECORD (для быстрого разбора «сырых» байт заголовка)
_REC_SIZE = sizeof(EVENT_RECORD)
_O_FLAGS = EVENT_HEADER.Flags.offset
_O_PID = EVENT_HEADER.ProcessId.offset
_O_TS = EVENT_HEADER.TimeStamp.offset
_O_GUID = EVENT_HEADER.ProviderId.offset
_O_ID = EVENT_HEADER.EventDescriptor.offset + EVENT_DESCRIPTOR.Id.offset
_O_VER = EVENT_HEADER.EventDescriptor.offset + EVENT_DESCRIPTOR.Version.offset
_O_UDLEN = EVENT_RECORD.UserDataLength.offset
_O_UD = EVENT_RECORD.UserData.offset
_U16 = struct.Struct('<H').unpack_from
_U32 = struct.Struct('<I').unpack_from
_I64 = struct.Struct('<q').unpack_from
_PTR = struct.Struct('<Q' if sizeof(ctypes.c_void_p) == 8 else '<I').unpack_from

_NET_GUID = KERNEL_NETWORK.bytes_le
_PROC_GUID = KERNEL_PROCESS.bytes_le
_DNS_GUID = DNS_CLIENT.bytes_le
_LOST_GUID = RT_LOST_EVENT.bytes_le

# ------------------------------------------------ разбор описаний событий (TDH)

Prop = namedtuple('Prop', 'name flags intype outtype count length')


def _find_wnull(data, start):
    """Позиция двухбайтового нуля (конец UTF-16 строки) с чётным смещением."""
    i = data.find(b'\x00\x00', start)
    while i != -1 and (i - start) % 2:
        i = data.find(b'\x00\x00', i + 1)
    return i


def _read_wstr(raw, offset):
    if not offset or offset >= len(raw):
        return ''
    end = _find_wnull(raw, offset)
    if end < 0:
        end = len(raw)
    return raw[offset:end].decode('utf-16-le', 'replace')


def parse_trace_event_info(raw):
    """Байты TRACE_EVENT_INFO -> список верхнеуровневых свойств события."""
    top = struct.unpack_from('<I', raw, TRACE_EVENT_INFO.TopLevelPropertyCount.offset)[0]
    base = sizeof(TRACE_EVENT_INFO)
    step = sizeof(EVENT_PROPERTY_INFO)
    props = []
    for i in range(top):
        off = base + i * step
        if off + step > len(raw):
            break
        flags, name_off, intype, outtype, _map, count, length = \
            struct.unpack_from('<IIHHIHH', raw, off)
        props.append(Prop(_read_wstr(raw, name_off), flags, intype, outtype, count, length))
    return props


def fixed_size(intype, length, outtype, ptr_size):
    """Размер значения фиксированной длины или None для строк и т.п."""
    if intype in (TDH_INTYPE_POINTER, TDH_INTYPE_SIZET):
        return ptr_size
    size = _FIXED_SIZES.get(intype)
    if size:
        return size
    if intype == TDH_INTYPE_BINARY:
        if length:
            return length
        if outtype == TDH_OUTTYPE_IPV6:
            return 16
    return None


class Layout:
    """Скомпилированная раскладка начала события: struct + порядок нужных полей."""

    __slots__ = ('st', 'size', 'pick')

    def __init__(self, fmt, order):
        self.st = struct.Struct(fmt)
        self.size = self.st.size
        self.pick = operator.itemgetter(*order)

    def unpack(self, data):
        return self.pick(self.st.unpack_from(data))


NET_FIELDS = ('pid', 'size', 'daddr', 'saddr', 'dport', 'sport')
_INT_CODES = {1: 'B', 2: 'H', 4: 'I', 8: 'Q'}


def compile_layout(props, ptr_size, fields=NET_FIELDS):
    """Раскладка для быстрого разбора событий Kernel-Network.

    pid и size читаются как числа; адреса и порты — как сырые байты
    (в событиях они в сетевом порядке байт).
    """
    want = dict.fromkeys(fields)
    sizes = {}
    fmt = ['<']
    index = 0
    for prop in props:
        if prop.flags & (PROPERTY_STRUCT | PROPERTY_PARAM_LENGTH | PROPERTY_PARAM_COUNT):
            break
        if (prop.count or 1) > 1:
            break
        size = fixed_size(prop.intype, prop.length, prop.outtype, ptr_size)
        if size is None:
            break
        key = prop.name.lower()
        if key in want and want[key] is None:
            if key in ('pid', 'size'):
                code = _INT_CODES.get(size)
                if code is None:
                    return None
                fmt.append(code)
            else:
                fmt.append('%ds' % size)
            want[key] = index
            sizes[key] = size
            index += 1
            if all(v is not None for v in want.values()):
                break
        else:
            fmt.append('%dx' % size)
    if any(v is None for v in want.values()):
        return None
    if sizes.get('daddr') not in (4, 16) or sizes.get('saddr') != sizes.get('daddr'):
        return None
    if sizes.get('dport') != 2 or sizes.get('sport') != 2:
        return None
    return Layout(''.join(fmt), [want[f] for f in fields])


def fallback_layout(addr_len):
    """Раскладка по документации, если TDH недоступен: PID, size, daddr, saddr, dport, sport."""
    return Layout('<II%ds%ds2s2s' % (addr_len, addr_len), range(6))


def _ref_value(values, index):
    if index < len(values) and isinstance(values[index], int):
        return values[index]
    return None


def decode_payload(props, data, ptr_size):
    """Последовательный разбор полей события (для редких событий: процессы, DNS).

    Возвращает {имя поля в нижнем регистре: значение}. Разбор останавливается
    на первом поле, которое не удаётся разобрать.
    """
    out = {}
    values = []
    off = 0
    n = len(data)
    for prop in props:
        if prop.flags & PROPERTY_STRUCT:
            break
        count = prop.count or 1
        if prop.flags & PROPERTY_PARAM_COUNT:
            count = _ref_value(values, prop.count)
            if count is None:
                break
        length = prop.length
        if prop.flags & PROPERTY_PARAM_LENGTH:
            length = _ref_value(values, prop.length)
            if length is None:
                break
        it = prop.intype
        if count != 1:
            size = fixed_size(it, length, prop.outtype, ptr_size)
            if size is None or off + size * count > n:
                break
            value = data[off:off + size * count]
            off += size * count
        elif it == TDH_INTYPE_UNICODESTRING:
            if length:
                end = nxt = min(off + 2 * length, n)
            else:
                end = _find_wnull(data, off)
                if end < 0:
                    end = nxt = n
                else:
                    nxt = end + 2
            value = data[off:end].decode('utf-16-le', 'replace').rstrip('\x00')
            off = nxt
        elif it == TDH_INTYPE_ANSISTRING:
            if length:
                end = nxt = min(off + length, n)
            else:
                end = data.find(b'\x00', off)
                if end < 0:
                    end = nxt = n
                else:
                    nxt = end + 1
            value = data[off:end].decode('mbcs' if IS_WINDOWS else 'latin-1', 'replace')
            off = nxt
        elif it in (TDH_INTYPE_COUNTEDSTRING, TDH_INTYPE_COUNTEDANSISTRING):
            if off + 2 > n:
                break
            blen = _U16(data, off)[0]
            raw = data[off + 2:off + 2 + blen]
            value = raw.decode('utf-16-le' if it == TDH_INTYPE_COUNTEDSTRING else 'latin-1',
                               'replace')
            off += 2 + blen
        elif it in (TDH_INTYPE_SID, TDH_INTYPE_WBEMSID):
            start = off + (2 * ptr_size if it == TDH_INTYPE_WBEMSID else 0)
            if start + 8 > n:
                break
            end = start + 8 + 4 * data[start + 1]
            value = data[start:end]
            off = end
        else:
            size = fixed_size(it, length, prop.outtype, ptr_size)
            if size is None or off + size > n:
                break
            raw = data[off:off + size]
            off += size
            if it in _FLOAT_FORMATS:
                value = struct.unpack(_FLOAT_FORMATS[it], raw)[0]
            elif it == TDH_INTYPE_GUID:
                value = str(uuid.UUID(bytes_le=raw))
            elif it == TDH_INTYPE_BINARY or it == 18:
                value = raw
            else:
                value = int.from_bytes(raw, 'little', signed=it in _SIGNED_TYPES)
        values.append(value)
        out[prop.name.lower()] = value
    return out


# --------------------------------------------------------------- сеанс ETW

_FUNCTYPE = getattr(ctypes, 'WINFUNCTYPE', ctypes.CFUNCTYPE)
EVENT_RECORD_CALLBACK = _FUNCTYPE(None, ctypes.c_void_p)

if IS_WINDOWS:
    _advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)
    _tdh = ctypes.WinDLL('tdh')

    _StartTraceW = _advapi32.StartTraceW
    _StartTraceW.restype = ULONG
    _StartTraceW.argtypes = [POINTER(ULONG64), ctypes.c_wchar_p, POINTER(EVENT_TRACE_PROPERTIES)]
    _ControlTraceW = _advapi32.ControlTraceW
    _ControlTraceW.restype = ULONG
    _ControlTraceW.argtypes = [ULONG64, ctypes.c_wchar_p, POINTER(EVENT_TRACE_PROPERTIES), ULONG]
    _EnableTraceEx2 = _advapi32.EnableTraceEx2
    _EnableTraceEx2.restype = ULONG
    _EnableTraceEx2.argtypes = [ULONG64, POINTER(GUID), ULONG, UCHAR, ULONG64, ULONG64, ULONG,
                                POINTER(ENABLE_TRACE_PARAMETERS)]
    _OpenTraceW = _advapi32.OpenTraceW
    _OpenTraceW.restype = ULONG64
    _OpenTraceW.argtypes = [POINTER(EVENT_TRACE_LOGFILEW)]
    _ProcessTrace = _advapi32.ProcessTrace
    _ProcessTrace.restype = ULONG
    _ProcessTrace.argtypes = [POINTER(ULONG64), ULONG, ctypes.c_void_p, ctypes.c_void_p]
    _CloseTrace = _advapi32.CloseTrace
    _CloseTrace.restype = ULONG
    _CloseTrace.argtypes = [ULONG64]
    _TdhGetEventInformation = _tdh.TdhGetEventInformation
    _TdhGetEventInformation.restype = ULONG
    _TdhGetEventInformation.argtypes = [ctypes.c_void_p, ULONG, ctypes.c_void_p,
                                        ctypes.c_void_p, POINTER(ULONG)]


_ERROR_TEXT = {
    ERROR_ACCESS_DENIED: 'отказано в доступе — запустите программу от имени администратора',
    ERROR_NO_SYSTEM_RESOURCES: 'не хватает ресурсов: запущено слишком много сеансов трассировки',
    ERROR_ALREADY_EXISTS: 'сеанс трассировки с таким именем уже существует',
    ERROR_WMI_INSTANCE_NOT_FOUND: 'сеанс трассировки не найден',
}


class EtwError(Exception):
    def __init__(self, code, where):
        text = _ERROR_TEXT.get(code)
        if text is None and IS_WINDOWS:
            text = ctypes.FormatError(code).strip()
        super().__init__('%s: ошибка %d (%s)' % (where, code, text or '?'))
        self.code = code


def _make_properties(for_start):
    base = sizeof(EVENT_TRACE_PROPERTIES)
    name_bytes = 1024 * sizeof(WCHAR)
    buf = ctypes.create_string_buffer(base + 2 * name_bytes)
    props = EVENT_TRACE_PROPERTIES.from_buffer(buf)
    props.Wnode.BufferSize = len(buf)
    props.Wnode.Flags = WNODE_FLAG_TRACED_GUID
    props.LoggerNameOffset = base
    if for_start:
        props.Wnode.ClientContext = 1          # отметки времени по QPC
        props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE
        props.BufferSize = 64                  # КБ
        props.MinimumBuffers = 8
        props.MaximumBuffers = 128
        props.FlushTimer = 1                   # события доходят не позже чем через ~1 с
    else:
        props.LogFileNameOffset = base + name_bytes
    return buf, props


class EtwSession:
    """Сеанс ETW реального времени. События передаются в sink (model.Model)."""

    def __init__(self, sink, name='NetActivityMonitor', dns=True, processes=True, use_filter=True):
        self.sink = sink
        self.use_filter = use_filter
        self.name = name
        self.want_dns = dns
        self.want_processes = processes
        self.events = 0
        self.errors = 0
        self.rt_lost = 0
        self.last_error = ''
        self.running = False
        self._session = 0
        self._trace = None
        self._thread = None
        self._callback = EVENT_RECORD_CALLBACK(self._on_event)
        self._logfile = None
        self._net_layouts = {}
        self._generic = {}

    # ---- запуск / остановка

    def start(self):
        if not IS_WINDOWS:
            raise EtwError(50, 'ETW доступен только в Windows')
        buf, props = _make_properties(True)
        handle = ULONG64(0)
        rc = _StartTraceW(byref(handle), self.name, props)
        if rc == ERROR_ALREADY_EXISTS:
            # остался сеанс от предыдущего запуска (например, после аварийного выхода)
            log.info('останавливаю старый сеанс %s', self.name)
            sbuf, sprops = _make_properties(False)
            _ControlTraceW(0, self.name, sprops, EVENT_TRACE_CONTROL_STOP)
            buf, props = _make_properties(True)
            rc = _StartTraceW(byref(handle), self.name, props)
        if rc:
            raise EtwError(rc, 'StartTrace')
        self._session = handle.value
        try:
            rc = self._enable(KERNEL_NETWORK, TRACE_LEVEL_VERBOSE, ALL_KEYWORDS,
                              sorted(NET_EVENTS))
            if rc:
                raise EtwError(rc, 'EnableTraceEx2 (Kernel-Network)')
            if self.want_processes:
                rc = self._enable(KERNEL_PROCESS, TRACE_LEVEL_VERBOSE,
                                  KERNEL_PROCESS_KEYWORD_PROCESS, [PROCESS_START, PROCESS_STOP])
                if rc:
                    log.warning('Kernel-Process не включён: %s', EtwError(rc, 'EnableTraceEx2'))
            if self.want_dns:
                rc = self._enable(DNS_CLIENT, TRACE_LEVEL_VERBOSE, ALL_KEYWORDS, list(DNS_EVENTS))
                if rc:
                    log.warning('DNS-Client не включён: %s', EtwError(rc, 'EnableTraceEx2'))
            self._open()
        except Exception:
            self._stop_session()
            raise
        self.running = True
        self._thread = threading.Thread(target=self._run, name='etw-consumer', daemon=True)
        self._thread.start()
        log.info('сеанс ETW %s запущен', self.name)

    def _enable(self, provider, level, keywords, event_ids):
        guid = GUID.from_uuid(provider)
        if event_ids and self.use_filter:
            # фильтр по id событий (Windows 8.1+): лишние события даже не попадают в буферы
            ids = list(event_ids)
            blob = struct.pack('<BBH%dH' % len(ids), 1, 0, len(ids), *ids)
            fbuf = ctypes.create_string_buffer(blob, len(blob))
            desc = EVENT_FILTER_DESCRIPTOR(ctypes.addressof(fbuf), len(blob),
                                           EVENT_FILTER_TYPE_EVENT_ID)
            params = ENABLE_TRACE_PARAMETERS()
            params.Version = ENABLE_TRACE_PARAMETERS_VERSION_2
            params.EnableFilterDesc = ctypes.pointer(desc)
            params.FilterDescCount = 1
            rc = _EnableTraceEx2(self._session, byref(guid), EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                                 level, keywords, 0, 0, byref(params))
            if rc == 0:
                return 0
            log.info('фильтр событий для %s не поддерживается (ошибка %d)', provider, rc)
        return _EnableTraceEx2(self._session, byref(guid), EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                               level, keywords, 0, 0, None)

    def _open(self):
        logfile = EVENT_TRACE_LOGFILEW()
        logfile.LoggerName = self.name
        logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD
        logfile.EventRecordCallback = ctypes.cast(self._callback, ctypes.c_void_p).value
        handle = _OpenTraceW(byref(logfile))
        if handle in INVALID_PROCESSTRACE_HANDLE:
            raise EtwError(ctypes.get_last_error(), 'OpenTrace')
        self._logfile = logfile
        self._trace = handle

    def _run(self):
        handles = (ULONG64 * 1)(self._trace)
        rc = _ProcessTrace(handles, 1, None, None)
        self.running = False
        if rc not in (0, ERROR_CANCELLED, ERROR_CTX_CLOSE_PENDING):
            self.last_error = str(EtwError(rc, 'ProcessTrace'))
            log.error(self.last_error)
        log.info('приём событий ETW завершён (код %d)', rc)

    def _stop_session(self):
        if self._session:
            _buf, props = _make_properties(False)
            _ControlTraceW(self._session, None, props, EVENT_TRACE_CONTROL_STOP)
            self._session = 0

    def stop(self):
        if self._trace is not None:
            _CloseTrace(self._trace)
            self._trace = None
        self._stop_session()
        if self._thread is not None:
            self._thread.join(5)
            self._thread = None
        self.running = False

    def stats(self):
        result = {'events': self.events, 'errors': self.errors, 'lost': self.rt_lost,
                  'running': self.running, 'error': self.last_error}
        if self._session:
            _buf, props = _make_properties(False)
            if _ControlTraceW(self._session, None, props, EVENT_TRACE_CONTROL_QUERY) == 0:
                result['lost'] += props.EventsLost + props.RealTimeBuffersLost
        return result

    # ---- обработка событий (поток ProcessTrace)

    def _on_event(self, addr):
        try:
            self.events += 1
            hdr = ctypes.string_at(addr, _REC_SIZE)
            guid = hdr[_O_GUID:_O_GUID + 16]
            if guid == _NET_GUID:
                self._on_net(addr, hdr)
            elif guid == _PROC_GUID:
                self._on_process(addr, hdr)
            elif guid == _DNS_GUID:
                self._on_dns(addr, hdr)
            elif guid == _LOST_GUID:
                self.rt_lost += 1
        except Exception as exc:  # исключение не должно уйти в ProcessTrace
            self.errors += 1
            self.last_error = 'разбор события: %r' % (exc,)
            if self.errors <= 20:
                log.exception('ошибка разбора события ETW')

    def _event_props(self, addr):
        size = ULONG(0)
        rc = _TdhGetEventInformation(addr, 0, None, None, byref(size))
        if rc != ERROR_INSUFFICIENT_BUFFER or not size.value:
            return None
        buf = ctypes.create_string_buffer(size.value)
        rc = _TdhGetEventInformation(addr, 0, None, buf, byref(size))
        if rc:
            return None
        return parse_trace_event_info(buf.raw)

    def _net_layout(self, addr, eid, ptr_size):
        props = self._event_props(addr)
        layout = compile_layout(props, ptr_size) if props else None
        if layout is None:
            layout = fallback_layout(16 if eid in IPV6_EVENTS else 4)
            log.warning('событие Kernel-Network %d: раскладка по умолчанию (свойства: %s)',
                        eid, props)
        else:
            log.info('событие Kernel-Network %d: %s', eid, [p.name for p in props])
        return layout

    def _on_net(self, addr, hdr):
        eid = _U16(hdr, _O_ID)[0]
        kind = NET_EVENTS.get(eid)
        if kind is None:
            return
        ptr_size = 4 if _U16(hdr, _O_FLAGS)[0] & EVENT_HEADER_FLAG_32_BIT_HEADER else 8
        key = (eid, hdr[_O_VER], ptr_size)
        layout = self._net_layouts.get(key)
        if layout is None:
            layout = self._net_layouts[key] = self._net_layout(addr, eid, ptr_size)
        if _U16(hdr, _O_UDLEN)[0] < layout.size:
            return
        data = ctypes.string_at(_PTR(hdr, _O_UD)[0], layout.size)
        pid, size, daddr, saddr, dport, sport = layout.unpack(data)
        proto, what = kind
        if what == ACCEPT:
            self.sink.on_accept(pid, sport)
            return
        ts = (_I64(hdr, _O_TS)[0] - FILETIME_UNIX_EPOCH) * 1e-7
        self.sink.on_traffic(pid, proto, what == SEND, size, daddr, dport, saddr, sport, ts)

    def _decode(self, addr, hdr):
        ptr_size = 4 if _U16(hdr, _O_FLAGS)[0] & EVENT_HEADER_FLAG_32_BIT_HEADER else 8
        key = (hdr[_O_GUID:_O_GUID + 16], _U16(hdr, _O_ID)[0], hdr[_O_VER], ptr_size)
        props = self._generic.get(key, False)
        if props is False:
            props = self._generic[key] = self._event_props(addr)
            if not props:
                log.warning('нет описания события %r', key[1:])
        if not props:
            return None
        length = _U16(hdr, _O_UDLEN)[0]
        data = ctypes.string_at(_PTR(hdr, _O_UD)[0], length) if length else b''
        return decode_payload(props, data, ptr_size)

    def _timestamp(self, hdr):
        return (_I64(hdr, _O_TS)[0] - FILETIME_UNIX_EPOCH) * 1e-7

    def _on_process(self, addr, hdr):
        eid = _U16(hdr, _O_ID)[0]
        if eid not in (PROCESS_START, PROCESS_STOP):
            return
        fields = self._decode(addr, hdr)
        if not fields or not isinstance(fields.get('processid'), int):
            return
        pid = fields['processid']
        if eid == PROCESS_START:
            image = fields.get('imagename')
            self.sink.on_process_start(pid, self._timestamp(hdr),
                                       image if isinstance(image, str) else '')
        else:
            self.sink.on_process_stop(pid, self._timestamp(hdr))

    def _on_dns(self, addr, hdr):
        if _U16(hdr, _O_ID)[0] not in DNS_EVENTS:
            return
        fields = self._decode(addr, hdr)
        if not fields:
            return
        name = fields.get('queryname')
        results = fields.get('queryresults')
        if isinstance(name, str) and isinstance(results, str) and name and results:
            self.sink.on_dns(_U32(hdr, _O_PID)[0], name, results, self._timestamp(hdr))
