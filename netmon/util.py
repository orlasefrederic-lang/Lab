"""Вспомогательные функции: IP-адреса, форматирование, расчёт скорости."""

import ipaddress
import socket
import time
from collections import deque

_V4_MAPPED_PREFIX = b'\x00' * 10 + b'\xff\xff'


def ip_from_bytes(raw):
    """IPv4/IPv6-адрес из 4 или 16 байт (сетевой порядок) в текст.

    Адреса вида ::ffff:1.2.3.4 превращаются в обычный IPv4.
    """
    if len(raw) == 4:
        return socket.inet_ntoa(raw)
    if len(raw) == 16:
        if raw[:12] == _V4_MAPPED_PREFIX:
            return socket.inet_ntoa(raw[12:])
        return str(ipaddress.IPv6Address(bytes(raw)))
    return bytes(raw).hex()


def normalize_ip(text):
    """Приводит текстовый адрес к тому же виду, что и ip_from_bytes()."""
    if not text:
        return None
    text = text.strip().strip('[]').split('%', 1)[0]
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return None
    if ip.version == 6 and ip.ipv4_mapped is not None:
        return str(ip.ipv4_mapped)
    return str(ip)


_CATEGORY_CACHE = {}

CATEGORY_LABELS = {
    'loopback': '(этот компьютер)',
    'lan': '(локальная сеть)',
    'multicast': '(групповая рассылка)',
    'broadcast': '(широковещательная рассылка)',
    'link-local': '(локальный сегмент)',
    'unspecified': '',
    'public': '',
    'other': '',
}


def ip_category(ip):
    """'loopback', 'lan', 'multicast', 'broadcast', 'link-local', 'public'..."""
    cat = _CATEGORY_CACHE.get(ip)
    if cat is None:
        cat = _category(ip)
        if len(_CATEGORY_CACHE) > 100000:
            _CATEGORY_CACHE.clear()
        _CATEGORY_CACHE[ip] = cat
    return cat


def _category(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return 'other'
    if addr.is_loopback:
        return 'loopback'
    if addr.is_unspecified:
        return 'unspecified'
    if addr.is_multicast:
        return 'multicast'
    if ip == '255.255.255.255':
        return 'broadcast'
    if addr.is_link_local:
        return 'link-local'
    if addr.is_private:
        return 'lan'
    return 'public'


def parse_dns_results(text):
    """Разбирает поле QueryResults событий DNS-Client.

    Пример: "type:  5 edge.example.net;::ffff:93.184.216.34;2606:2800::1;"
    Возвращает список IP-адресов (записи CNAME пропускаются).
    """
    ips = []
    for token in (text or '').split(';'):
        token = token.strip()
        if not token or token.startswith('type:'):
            continue
        ip = normalize_ip(token)
        if ip and ip not in ips:
            ips.append(ip)
    return ips


# ----------------------------------------------------------------- форматирование

_UNITS = ('Б', 'КБ', 'МБ', 'ГБ', 'ТБ')


def fmt_bytes(n):
    """1536 -> '1,5 КБ'."""
    if n is None:
        return ''
    value = float(n)
    for unit in _UNITS:
        if abs(value) < 1024 or unit == _UNITS[-1]:
            if unit == 'Б':
                return '%d Б' % value
            return ('%.1f %s' % (value, unit)).replace('.', ',')
        value /= 1024.0
    return ''


def fmt_rate(bytes_per_sec):
    if not bytes_per_sec or bytes_per_sec < 1:
        return ''
    return fmt_bytes(bytes_per_sec) + '/с'


def fmt_time(ts, now=None):
    """Время: сегодня — 'ЧЧ:ММ:СС', в этом году — 'ДД.ММ ЧЧ:ММ', иначе с годом."""
    if not ts:
        return ''
    now = time.time() if now is None else now
    t = time.localtime(ts)
    n = time.localtime(now)
    if t.tm_year == n.tm_year and t.tm_yday == n.tm_yday:
        return time.strftime('%H:%M:%S', t)
    if t.tm_year == n.tm_year:
        return time.strftime('%d.%m %H:%M', t)
    return time.strftime('%d.%m.%Y %H:%M', t)


def fmt_datetime(ts):
    if not ts:
        return ''
    return time.strftime('%d.%m.%Y %H:%M:%S', time.localtime(ts))


WELL_KNOWN_PORTS = {
    20: 'ftp-data', 21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
    67: 'dhcp', 68: 'dhcp', 80: 'http', 88: 'kerberos', 110: 'pop3', 123: 'ntp',
    137: 'netbios', 138: 'netbios', 139: 'netbios', 143: 'imap', 161: 'snmp',
    389: 'ldap', 443: 'https', 445: 'smb', 465: 'smtps', 500: 'ipsec',
    546: 'dhcpv6', 547: 'dhcpv6', 587: 'smtp', 636: 'ldaps', 853: 'dns-over-tls',
    993: 'imaps', 995: 'pop3s', 1080: 'socks', 1194: 'openvpn', 1900: 'ssdp',
    3074: 'xbox', 3389: 'rdp', 3478: 'stun', 3479: 'stun', 4500: 'ipsec-nat',
    5222: 'xmpp', 5228: 'google-push', 5353: 'mdns', 5355: 'llmnr', 5938: 'teamviewer',
    6881: 'bittorrent', 7680: 'delivery-opt', 8080: 'http-alt', 8443: 'https-alt',
    9001: 'tor', 9050: 'tor', 51820: 'wireguard',
}


def port_label(port):
    name = WELL_KNOWN_PORTS.get(port)
    return '%d (%s)' % (port, name) if name else str(port)


class RateTracker:
    """Скорость (байт/с) по нарастающим счётчикам за скользящее окно."""

    def __init__(self, window=3.0):
        self.window = window
        self._hist = {}

    def update(self, key, now, sent, recv):
        dq = self._hist.get(key)
        if dq is None:
            dq = self._hist[key] = deque()
        if dq and (sent < dq[-1][1] or recv < dq[-1][2]):
            dq.clear()  # счётчики сброшены (очистка истории, смена фильтра)
        dq.append((now, sent, recv))
        # dq[0] — самая свежая точка, которая старше окна
        while len(dq) > 1 and now - dq[1][0] >= self.window:
            dq.popleft()
        t0, s0, r0 = dq[0]
        dt = now - t0
        if dt <= 0:
            return 0.0, 0.0
        return (sent - s0) / dt, (recv - r0) / dt

    def forget_except(self, keys):
        for key in list(self._hist):
            if key not in keys:
                del self._hist[key]
