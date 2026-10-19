package lab.netstrazh.vpn

import lab.netstrazh.net.Dns
import lab.netstrazh.net.DnsTcp
import lab.netstrazh.net.HttpConnect
import lab.netstrazh.net.ProxyException
import lab.netstrazh.net.Socks5
import lab.netstrazh.net.withDeadline
import java.io.IOException
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.nio.channels.SocketChannel

/** Checks a proxy configuration end to end: reachability, exit IP/country and UDP support. */
class ProxyTester(
    private val protectTcp: (Socket) -> Boolean,
    private val protectUdp: (DatagramSocket) -> Boolean,
) {
    class Result(val ok: Boolean, val lines: List<String>, val udp: Boolean?)

    private val cloudflare = InetAddress.getByAddress(byteArrayOf(1, 1, 1, 1))

    fun run(c: ProxyConfig, proxy: InetSocketAddress): Result {
        val lines = ArrayList<String>()
        // 1. Reachability and the exit address (Cloudflare's trace page reports the client IP and country).
        val trace = try {
            val ch = SocketChannel.open()
            try {
                protectTcp(ch.socket())
                ch.socket().connect(proxy, 4000)
                lines += "✓ прокси ${proxy.address.hostAddress}:${proxy.port} отвечает"
                withDeadline(ch, 15_000) {
                    val dst = InetSocketAddress(cloudflare, 80)
                    if (c.type == ProxyType.HTTP) HttpConnect.connect(ch, c.user, c.pass, dst)
                    else Socks5.connect(ch, c.user, c.pass, dst)
                    val req = "GET /cdn-cgi/trace HTTP/1.1\r\nHost: 1.1.1.1\r\nUser-Agent: NetStrazh\r\nConnection: close\r\n\r\n"
                    ch.write(ByteBuffer.wrap(req.toByteArray()))
                    val sb = StringBuilder()
                    val bb = ByteBuffer.allocate(4096)
                    while (sb.length < 8192) {
                        bb.clear()
                        if (ch.read(bb) < 0) break
                        sb.append(String(bb.array(), 0, bb.position(), Charsets.ISO_8859_1))
                    }
                    sb.toString()
                }
            } finally {
                Engine.closeQuietly(ch)
            }
        } catch (e: ProxyException) {
            lines += "✗ " + (e.message ?: "прокси отказал")
            return Result(false, lines, null)
        } catch (e: IOException) {
            lines += if (lines.isEmpty()) "✗ прокси не отвечает (${e.message ?: "нет соединения"}). " +
                "Включён ли режим прокси в VPN-приложении и верен ли порт?"
            else "✗ через прокси нет доступа в интернет (${e.message ?: "ошибка"})"
            return Result(false, lines, null)
        }
        val ip = Regex("(?m)^ip=(.+)$").find(trace)?.groupValues?.get(1)?.trim()
        val loc = Regex("(?m)^loc=(.+)$").find(trace)?.groupValues?.get(1)?.trim()
        lines += if (ip != null) "✓ выход в интернет: $ip" + (if (loc != null) " (${countryName(loc)})" else "")
        else "✓ соединение через прокси работает"

        // 2. DNS over TCP through the proxy, if enabled (some HTTP proxies only allow CONNECT to port 443).
        if (c.dnsViaProxy) {
            lines += try {
                if (dnsWorks(c, proxy)) "✓ DNS через прокси (${c.dnsServer}) работает"
                else "✗ DNS через прокси не отвечает: снимите галочку «DNS через прокси» или смените DNS-сервер"
            } catch (e: Exception) {
                "✗ DNS через прокси не работает (${e.message ?: "ошибка"}): снимите галочку «DNS через прокси» или смените DNS-сервер"
            }
        }

        // 3. UDP (SOCKS5 only): a DNS query through UDP ASSOCIATE.
        var udp: Boolean? = null
        if (c.type == ProxyType.SOCKS5) {
            udp = try { udpWorks(c, proxy) } catch (_: Exception) { false }
            lines += if (udp) "✓ UDP через прокси работает (звонки, QUIC, игры)"
            else "✗ прокси не передаёт UDP: " + if (c.udpDirect) "UDP пойдёт напрямую" else "UDP будет заблокирован (звонки могут не работать)"
        } else {
            lines += "• HTTP-прокси не передаёт UDP: " + if (c.udpDirect) "UDP пойдёт напрямую" else "UDP будет заблокирован"
        }
        if (c.user.isEmpty() && lab.netstrazh.net.isLoopback(proxy.address)) {
            lines += "⚠ прокси без пароля: любое приложение на телефоне может подключиться к нему напрямую, " +
                "мимо Стража и его блокировок. Задайте логин и пароль для прокси в VPN-приложении и здесь."
        }
        return Result(true, lines, udp)
    }

    private fun dnsQuery(): ByteArray = byteArrayOf(0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7) + "example".toByteArray() +
        byteArrayOf(3) + "com".toByteArray() + byteArrayOf(0, 0, 1, 0, 1)

    private fun dnsWorks(c: ProxyConfig, proxy: InetSocketAddress): Boolean {
        val server = Upstream.ipOrNull(c.dnsServer) ?: return false
        val ch = SocketChannel.open()
        try {
            protectTcp(ch.socket())
            ch.socket().connect(proxy, 4000)
            return withDeadline(ch, 10_000) {
                val dst = InetSocketAddress(server, 53)
                if (c.type == ProxyType.HTTP) HttpConnect.connect(ch, c.user, c.pass, dst)
                else Socks5.connect(ch, c.user, c.pass, dst)
                val q = dnsQuery()
                val r = DnsTcp.query(ch, q, 0, q.size)
                Dns.parse(r, 0, r.size)?.id == 0x1234
            }
        } finally {
            Engine.closeQuietly(ch)
        }
    }

    private fun udpWorks(c: ProxyConfig, proxy: InetSocketAddress): Boolean {
        val ctl = SocketChannel.open()
        val dc = DatagramChannel.open()
        try {
            protectTcp(ctl.socket())
            ctl.socket().connect(proxy, 4000)
            val relay = withDeadline(ctl, 8000) { Socks5.udpAssociate(ctl, c.user, c.pass, proxy) }
            protectUdp(dc.socket())
            dc.connect(relay)
            dc.socket().soTimeout = 4000
            val out = Socks5.udpHeader(cloudflare, 53) + dnsQuery()
            repeat(2) {
                dc.socket().send(java.net.DatagramPacket(out, out.size))
                val buf = ByteArray(2048)
                val p = java.net.DatagramPacket(buf, buf.size)
                try {
                    dc.socket().receive(p)
                    val off = Socks5.udpPayloadOffset(buf, p.length)
                    if (off >= 0 && Dns.parse(buf, off, p.length - off)?.id == 0x1234) return true
                } catch (_: java.net.SocketTimeoutException) {
                }
            }
            return false
        } finally {
            Engine.closeQuietly(dc)
            Engine.closeQuietly(ctl)
        }
    }

    companion object {
        private val countries = mapOf(
            "RU" to "Россия", "NL" to "Нидерланды", "DE" to "Германия", "FI" to "Финляндия", "SE" to "Швеция",
            "US" to "США", "GB" to "Великобритания", "FR" to "Франция", "PL" to "Польша", "LV" to "Латвия",
            "LT" to "Литва", "EE" to "Эстония", "KZ" to "Казахстан", "TR" to "Турция", "AE" to "ОАЭ",
            "CH" to "Швейцария", "AT" to "Австрия", "CZ" to "Чехия", "JP" to "Япония", "SG" to "Сингапур",
            "GE" to "Грузия", "AM" to "Армения", "RS" to "Сербия", "BY" to "Беларусь", "UA" to "Украина",
            "CA" to "Канада", "IT" to "Италия", "ES" to "Испания", "MD" to "Молдова", "HK" to "Гонконг",
        )

        fun countryName(code: String): String = countries[code.uppercase()]?.let { "$it, $code" } ?: code
    }
}
