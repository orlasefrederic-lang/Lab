"""Разбор событий ETW: раскладка структур, TDH-описания, обработчик событий."""

import ctypes
import os
import socket
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import etw  # noqa: E402
from etw import (DNS_CLIENT, EVENT_RECORD, KERNEL_NETWORK, KERNEL_PROCESS, Prop,  # noqa: E402
                 compile_layout, decode_payload, fallback_layout, parse_trace_event_info)
from winapi import FILETIME_UNIX_EPOCH, GUID  # noqa: E402

U8, U16, U32, U64, UNICODE, ANSI, BINARY, POINTER, FILETIME = 4, 6, 8, 10, 1, 2, 14, 16, 17
OUT_IPV4, OUT_IPV6, OUT_PORT = 23, 24, 22


def build_trace_event_info(props):
    """Собирает байты TRACE_EVENT_INFO так, как их вернул бы TdhGetEventInformation."""
    head = ctypes.sizeof(etw.TRACE_EVENT_INFO)
    step = ctypes.sizeof(etw.EVENT_PROPERTY_INFO)
    names = b''
    names_base = head + step * len(props)
    entries = b''
    for name, intype, outtype, flags, count, length in props:
        offset = names_base + len(names)
        names += name.encode('utf-16-le') + b'\x00\x00'
        entries += struct.pack('<IIHHIHHI', flags, offset, intype, outtype, 0, count, length, 0)
    header = bytearray(head)
    struct.pack_into('<II', header, etw.TRACE_EVENT_INFO.PropertyCount.offset,
                     len(props), len(props))
    return bytes(header) + entries + names


def tcp_props(v6=False):
    addr = (BINARY, OUT_IPV6, 0, 1, 16) if v6 else (U32, OUT_IPV4, 0, 1, 0)
    return [
        ('PID', U32, 0, 0, 1, 0), ('size', U32, 0, 0, 1, 0),
        ('daddr',) + addr, ('saddr',) + addr,
        ('dport', U16, OUT_PORT, 0, 1, 0), ('sport', U16, OUT_PORT, 0, 1, 0),
        ('startime', U32, 0, 0, 1, 0), ('endtime', U32, 0, 0, 1, 0),
        ('seqnum', U32, 0, 0, 1, 0), ('connid', POINTER, 0, 0, 1, 0),
    ]


def tcp_payload(pid, size, daddr, saddr, dport, sport, v6=False):
    family = socket.AF_INET6 if v6 else socket.AF_INET
    return (struct.pack('<II', pid, size) + socket.inet_pton(family, daddr)
            + socket.inet_pton(family, saddr) + dport.to_bytes(2, 'big')
            + sport.to_bytes(2, 'big') + struct.pack('<IIIQ', 1, 2, 3, 0xDEAD))


def wstr(text):
    return text.encode('utf-16-le') + b'\x00\x00'


@unittest.skipUnless(ctypes.sizeof(ctypes.c_void_p) == 8, 'размеры проверяются для x64')
class StructLayoutTest(unittest.TestCase):
    """Размеры и смещения должны совпадать с заголовками Windows SDK (x64)."""

    def test_sizes(self):
        expected = {
            etw.EVENT_DESCRIPTOR: 16, etw.EVENT_HEADER: 80, etw.EVENT_RECORD: 112,
            etw.WNODE_HEADER: 48, etw.EVENT_TRACE_PROPERTIES: 120,
            etw.EVENT_TRACE_HEADER: 48, etw.EVENT_TRACE: 88,
            etw.TIME_ZONE_INFORMATION: 172, etw.TRACE_LOGFILE_HEADER: 280,
            etw.EVENT_TRACE_LOGFILEW: 448, etw.EVENT_FILTER_DESCRIPTOR: 16,
            etw.ENABLE_TRACE_PARAMETERS: 48, etw.EVENT_PROPERTY_INFO: 24,
            etw.TRACE_EVENT_INFO: 112, GUID: 16,
        }
        for struct_type, size in expected.items():
            self.assertEqual(ctypes.sizeof(struct_type), size, struct_type.__name__)

    def test_offsets(self):
        self.assertEqual(etw.EVENT_HEADER.Flags.offset, 4)
        self.assertEqual(etw.EVENT_HEADER.ProcessId.offset, 12)
        self.assertEqual(etw.EVENT_HEADER.TimeStamp.offset, 16)
        self.assertEqual(etw.EVENT_HEADER.ProviderId.offset, 24)
        self.assertEqual(etw.EVENT_HEADER.EventDescriptor.offset, 40)
        self.assertEqual(etw.EVENT_RECORD.UserDataLength.offset, 86)
        self.assertEqual(etw.EVENT_RECORD.UserData.offset, 96)
        self.assertEqual(etw.EVENT_TRACE_PROPERTIES.LoggerThreadId.offset, 104)
        self.assertEqual(etw.EVENT_TRACE_PROPERTIES.LoggerNameOffset.offset, 116)
        self.assertEqual(etw.EVENT_TRACE_LOGFILEW.CurrentEvent.offset, 32)
        self.assertEqual(etw.EVENT_TRACE_LOGFILEW.LogfileHeader.offset, 120)
        self.assertEqual(etw.EVENT_TRACE_LOGFILEW.BufferCallback.offset, 400)
        self.assertEqual(etw.EVENT_TRACE_LOGFILEW.EventRecordCallback.offset, 424)
        self.assertEqual(etw.TRACE_LOGFILE_HEADER.BootTime.offset, 248)
        self.assertEqual(etw.ENABLE_TRACE_PARAMETERS.EnableFilterDesc.offset, 32)
        self.assertEqual(etw.TRACE_EVENT_INFO.TopLevelPropertyCount.offset, 104)


class TdhTest(unittest.TestCase):
    def test_parse_trace_event_info(self):
        props = parse_trace_event_info(build_trace_event_info(tcp_props()))
        self.assertEqual([p.name for p in props][:6], ['PID', 'size', 'daddr', 'saddr', 'dport', 'sport'])
        self.assertEqual(props[2].outtype, OUT_IPV4)
        self.assertEqual(props[-1].intype, POINTER)

    def test_tcp_v4_layout(self):
        props = parse_trace_event_info(build_trace_event_info(tcp_props()))
        layout = compile_layout(props, 8)
        self.assertEqual(layout.size, 20)
        data = tcp_payload(4321, 1460, '93.184.216.34', '192.168.1.5', 443, 50123)
        pid, size, daddr, saddr, dport, sport = layout.unpack(data)
        self.assertEqual((pid, size), (4321, 1460))
        self.assertEqual(socket.inet_ntoa(daddr), '93.184.216.34')
        self.assertEqual(socket.inet_ntoa(saddr), '192.168.1.5')
        self.assertEqual(int.from_bytes(dport, 'big'), 443)
        self.assertEqual(int.from_bytes(sport, 'big'), 50123)
        self.assertEqual(fallback_layout(4).unpack(data), layout.unpack(data))

    def test_tcp_v6_layout(self):
        props = parse_trace_event_info(build_trace_event_info(tcp_props(v6=True)))
        layout = compile_layout(props, 8)
        data = tcp_payload(7, 99, '2606:2800::1', 'fe80::1', 443, 60000, v6=True)
        pid, size, daddr, saddr, dport, sport = layout.unpack(data)
        self.assertEqual(socket.inet_ntop(socket.AF_INET6, daddr), '2606:2800::1')
        self.assertEqual(int.from_bytes(sport, 'big'), 60000)
        self.assertEqual(fallback_layout(16).unpack(data), (pid, size, daddr, saddr, dport, sport))

    def test_ipv6_by_outtype_and_reordered_fields(self):
        props = [Prop('size', 0, U32, 0, 1, 0), Prop('connid', 0, POINTER, 0, 1, 0),
                 Prop('PID', 0, U32, 0, 1, 0), Prop('saddr', 0, BINARY, OUT_IPV6, 1, 0),
                 Prop('daddr', 0, BINARY, OUT_IPV6, 1, 0), Prop('sport', 0, U16, 0, 1, 0),
                 Prop('dport', 0, U16, 0, 1, 0)]
        layout = compile_layout(props, 4)
        data = (struct.pack('<III', 500, 0, 42) + b'\x11' * 16 + b'\x22' * 16
                + (1000).to_bytes(2, 'big') + (80).to_bytes(2, 'big'))
        pid, size, daddr, saddr, dport, sport = layout.unpack(data)
        self.assertEqual((pid, size), (42, 500))
        self.assertEqual((daddr, saddr), (b'\x22' * 16, b'\x11' * 16))
        self.assertEqual((int.from_bytes(dport, 'big'), int.from_bytes(sport, 'big')), (80, 1000))

    def test_layout_rejects_unknown_shapes(self):
        self.assertIsNone(compile_layout([Prop('PID', 0, U32, 0, 1, 0)], 8))
        bad_port = tcp_props()
        bad_port[4] = ('dport', U32, 0, 0, 1, 0)
        props = parse_trace_event_info(build_trace_event_info(bad_port))
        self.assertIsNone(compile_layout(props, 8))
        string_first = [Prop('name', 0, UNICODE, 0, 1, 0)] + list(
            parse_trace_event_info(build_trace_event_info(tcp_props())))
        self.assertIsNone(compile_layout(string_first, 8))

    def test_decode_process_start(self):
        props = parse_trace_event_info(build_trace_event_info([
            ('ProcessID', U32, 0, 0, 1, 0), ('ProcessSequenceNumber', U64, 0, 0, 1, 0),
            ('CreateTime', FILETIME, 0, 0, 1, 0), ('ParentProcessID', U32, 0, 0, 1, 0),
            ('ParentProcessSequenceNumber', U64, 0, 0, 1, 0), ('SessionID', U32, 0, 0, 1, 0),
            ('Flags', U32, 0, 0, 1, 0), ('ImageName', UNICODE, 0, 0, 1, 0),
            ('ImageChecksum', U32, 0, 0, 1, 0), ('TimeDateStamp', U32, 0, 0, 1, 0),
            ('PackageFullName', UNICODE, 0, 0, 1, 0), ('PackageRelativeAppId', UNICODE, 0, 0, 1, 0),
        ]))
        image = r'\Device\HarddiskVolume3\Windows\System32\curl.exe'
        data = (struct.pack('<IQQIQII', 9876, 55, 133000000000000000, 1200, 54, 1, 0)
                + wstr(image) + struct.pack('<II', 7, 8) + wstr('') + wstr('App'))
        fields = decode_payload(props, data, 8)
        self.assertEqual(fields['processid'], 9876)
        self.assertEqual(fields['parentprocessid'], 1200)
        self.assertEqual(fields['imagename'], image)
        self.assertEqual(fields['timedatestamp'], 8)
        self.assertEqual(fields['packagefullname'], '')
        self.assertEqual(fields['packagerelativeappid'], 'App')

    def test_decode_dns_and_param_length(self):
        props = parse_trace_event_info(build_trace_event_info([
            ('QueryName', UNICODE, 0, 0, 1, 0), ('QueryType', U32, 0, 0, 1, 0),
            ('QueryOptions', U64, 0, 0, 1, 0), ('QueryStatus', U32, 0, 0, 1, 0),
            ('QueryResults', UNICODE, 0, 0, 1, 0), ('BlobLen', U16, 0, 0, 1, 0),
            ('Blob', BINARY, 0, etw.PROPERTY_PARAM_LENGTH, 1, 5), ('Tail', U8, 0, 0, 1, 0),
        ]))
        results = 'type:  5 github.map.fastly.net;::ffff:140.82.121.4;'
        data = (wstr('github.com') + struct.pack('<IQI', 1, 0, 0) + wstr(results)
                + struct.pack('<H', 3) + b'abc' + b'\x07')
        fields = decode_payload(props, data, 8)
        self.assertEqual(fields['queryname'], 'github.com')
        self.assertEqual(fields['queryresults'], results)
        self.assertEqual(fields['blob'], b'abc')
        self.assertEqual(fields['tail'], 7)

    def test_decode_stops_on_truncated_data(self):
        props = [Prop('A', 0, U32, 0, 1, 0), Prop('B', 0, U64, 0, 1, 0)]
        self.assertEqual(decode_payload(props, struct.pack('<I', 5) + b'\x01', 8), {'a': 5})


class FakeSink:
    def __init__(self):
        self.calls = []

    def __getattr__(self, name):
        if not name.startswith('on_'):
            raise AttributeError(name)
        return lambda *args: self.calls.append((name,) + args)


class SessionCallbackTest(unittest.TestCase):
    """Проверка горячего пути: «сырые» байты EVENT_RECORD -> вызовы модели."""

    def setUp(self):
        self.sink = FakeSink()
        self.session = etw.EtwSession(self.sink)
        self.infos = {}
        self.session._event_props = lambda addr: self.infos.get(self._current)
        self._keep = []

    def fire(self, provider, event_id, payload, pid=0, filetime=133000000000000000, version=0):
        self._current = (provider, event_id)
        rec = EVENT_RECORD()
        rec.EventHeader.ProviderId = GUID.from_uuid(provider)
        rec.EventHeader.EventDescriptor.Id = event_id
        rec.EventHeader.EventDescriptor.Version = version
        rec.EventHeader.Flags = 0x40
        rec.EventHeader.ProcessId = pid
        rec.EventHeader.TimeStamp = filetime
        buf = ctypes.create_string_buffer(payload, len(payload))
        self._keep.append(buf)
        rec.UserData = ctypes.addressof(buf)
        rec.UserDataLength = len(payload)
        self.session._on_event(ctypes.addressof(rec))
        self.assertEqual(self.session.errors, 0, self.session.last_error)

    def test_network_events(self):
        info = parse_trace_event_info(build_trace_event_info(tcp_props()))
        self.infos[(KERNEL_NETWORK, 10)] = info
        self.infos[(KERNEL_NETWORK, 43)] = info
        ft = FILETIME_UNIX_EPOCH + 17_000_000_000 * 10_000_000
        self.fire(KERNEL_NETWORK, 10, tcp_payload(100, 1500, '1.2.3.4', '10.0.0.2', 443, 50000),
                  filetime=ft)
        self.fire(KERNEL_NETWORK, 43, tcp_payload(100, 60, '8.8.8.8', '10.0.0.2', 53, 50001))
        self.fire(KERNEL_NETWORK, 99, b'\x00' * 40)  # неизвестное событие игнорируется
        (name, pid, proto, send, size, daddr, dport, saddr, sport, ts), second = self.sink.calls
        self.assertEqual((name, pid, proto, send, size), ('on_traffic', 100, 'TCP', True, 1500))
        self.assertEqual(socket.inet_ntoa(daddr), '1.2.3.4')
        self.assertEqual(int.from_bytes(dport, 'big'), 443)
        self.assertAlmostEqual(ts, 17_000_000_000, places=3)
        self.assertEqual(second[2:5], ('UDP', False, 60))

    def test_network_fallback_without_tdh(self):
        self.fire(KERNEL_NETWORK, 26, tcp_payload(5, 10, '2001:db8::1', '2001:db8::2', 443,
                                                  49999, v6=True))
        call = self.sink.calls[0]
        self.assertEqual(call[:5], ('on_traffic', 5, 'TCP', True, 10))
        self.assertEqual(socket.inet_ntop(socket.AF_INET6, call[5]), '2001:db8::1')

    def test_short_payload_is_ignored(self):
        self.fire(KERNEL_NETWORK, 10, b'\x01\x00\x00\x00')
        self.assertEqual(self.sink.calls, [])

    def test_accept_process_and_dns(self):
        self.infos[(KERNEL_NETWORK, 15)] = parse_trace_event_info(build_trace_event_info(tcp_props()))
        self.fire(KERNEL_NETWORK, 15, tcp_payload(300, 0, '192.168.1.9', '192.168.1.2', 51000, 8080))
        self.infos[(KERNEL_PROCESS, 1)] = parse_trace_event_info(build_trace_event_info([
            ('ProcessID', U32, 0, 0, 1, 0), ('CreateTime', FILETIME, 0, 0, 1, 0),
            ('ParentProcessID', U32, 0, 0, 1, 0), ('SessionID', U32, 0, 0, 1, 0),
            ('ImageName', UNICODE, 0, 0, 1, 0)]))
        self.fire(KERNEL_PROCESS, 1, struct.pack('<IQII', 777, 1, 4, 1) + wstr(r'C:\x\app.exe'))
        self.infos[(KERNEL_PROCESS, 2)] = parse_trace_event_info(build_trace_event_info([
            ('ProcessID', U32, 0, 0, 1, 0), ('ImageName', ANSI, 0, 0, 1, 0)]))
        self.fire(KERNEL_PROCESS, 2, struct.pack('<I', 777) + b'app.exe\x00')
        self.infos[(DNS_CLIENT, 3008)] = parse_trace_event_info(build_trace_event_info([
            ('QueryName', UNICODE, 0, 0, 1, 0), ('QueryType', U32, 0, 0, 1, 0),
            ('QueryOptions', U64, 0, 0, 1, 0), ('QueryStatus', U32, 0, 0, 1, 0),
            ('QueryResults', UNICODE, 0, 0, 1, 0)]))
        self.fire(DNS_CLIENT, 3008, wstr('example.com') + struct.pack('<IQI', 1, 0, 0)
                  + wstr('::ffff:93.184.215.14;'), pid=777)
        names = [c[0] for c in self.sink.calls]
        self.assertEqual(names, ['on_accept', 'on_process_start', 'on_process_stop', 'on_dns'])
        self.assertEqual(int.from_bytes(self.sink.calls[0][2], 'big'), 8080)
        self.assertEqual(self.sink.calls[1][1], 777)
        self.assertEqual(self.sink.calls[1][3], r'C:\x\app.exe')
        self.assertEqual(self.sink.calls[3][1:4], (777, 'example.com', '::ffff:93.184.215.14;'))

    def test_errors_are_contained(self):
        self.session.sink = None  # любой вызов sink упадёт
        etw.log.disabled = True
        self.addCleanup(setattr, etw.log, 'disabled', False)
        self.infos[(KERNEL_NETWORK, 10)] = parse_trace_event_info(build_trace_event_info(tcp_props()))
        self._current = (KERNEL_NETWORK, 10)
        rec = EVENT_RECORD()
        rec.EventHeader.ProviderId = GUID.from_uuid(KERNEL_NETWORK)
        rec.EventHeader.EventDescriptor.Id = 10
        payload = tcp_payload(1, 1, '1.1.1.1', '2.2.2.2', 1, 2)
        buf = ctypes.create_string_buffer(payload, len(payload))
        rec.UserData = ctypes.addressof(buf)
        rec.UserDataLength = len(payload)
        self.session._on_event(ctypes.addressof(rec))
        self.assertEqual(self.session.errors, 1)


if __name__ == '__main__':
    unittest.main()
