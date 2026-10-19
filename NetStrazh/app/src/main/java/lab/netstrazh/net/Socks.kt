package lab.netstrazh.net

import java.io.IOException
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.SocketChannel
import java.util.Base64
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit

/** A proxy refused or failed a request. [code] is the SOCKS5 reply code (or HTTP status), -1 if none. */
class ProxyException(message: String, val code: Int = -1) : IOException(message)

/** Closes [ch] if [block] does not finish within [ms]; a blocked read then fails with an exception. */
fun <T> withDeadline(ch: SocketChannel, ms: Long, block: () -> T): T {
    val f: ScheduledFuture<*> = Deadline.timer.schedule({ try { ch.close() } catch (_: Exception) {} }, ms, TimeUnit.MILLISECONDS)
    try {
        return block()
    } catch (e: IOException) {
        if (!ch.isOpen && f.isDone) throw IOException("proxy timeout", e)
        throw e
    } finally {
        f.cancel(false)
    }
}

private object Deadline {
    val timer = Executors.newSingleThreadScheduledExecutor { r -> Thread(r, "ns-deadline").apply { isDaemon = true } }
}

private fun SocketChannel.writeAll(b: ByteArray) {
    val bb = ByteBuffer.wrap(b)
    while (bb.hasRemaining()) write(bb)
}

private fun SocketChannel.readFully(n: Int): ByteArray {
    val bb = ByteBuffer.allocate(n)
    while (bb.hasRemaining()) {
        if (read(bb) < 0) throw IOException("proxy closed the connection")
    }
    return bb.array()
}

/** SOCKS5 client (RFC 1928, username/password auth per RFC 1929) over a blocking SocketChannel. */
object Socks5 {
    const val CMD_CONNECT = 1
    const val CMD_UDP_ASSOCIATE = 3

    fun replyText(code: Int): String = when (code) {
        1 -> "общая ошибка сервера"
        2 -> "запрещено правилами прокси"
        3 -> "сеть недоступна"
        4 -> "узел недоступен"
        5 -> "соединение отклонено"
        6 -> "истёк TTL"
        7 -> "команда не поддерживается"
        8 -> "тип адреса не поддерживается"
        else -> "код $code"
    }

    fun greeting(withAuth: Boolean): ByteArray =
        if (withAuth) byteArrayOf(5, 2, 0, 2) else byteArrayOf(5, 1, 0)

    fun authRequest(user: String, pass: String): ByteArray {
        val u = user.toByteArray(Charsets.UTF_8)
        val p = pass.toByteArray(Charsets.UTF_8)
        require(u.size in 1..255 && p.size <= 255) { "login/password too long" }
        return byteArrayOf(1, u.size.toByte()) + u + byteArrayOf(p.size.toByte()) + p
    }

    /** Encodes ATYP + address + port. */
    fun address(addr: InetAddress, port: Int): ByteArray {
        val a = addr.address
        val head = byteArrayOf(if (a.size == 4) 1 else 4)
        return head + a + byteArrayOf((port ushr 8).toByte(), port.toByte())
    }

    fun request(cmd: Int, addr: InetAddress, port: Int): ByteArray =
        byteArrayOf(5, cmd.toByte(), 0) + address(addr, port)

    /** Greeting and (optional) authentication. */
    fun handshake(ch: SocketChannel, user: String, pass: String) {
        val auth = user.isNotEmpty()
        ch.writeAll(greeting(auth))
        val sel = ch.readFully(2)
        if (sel[0].toInt() != 5) throw ProxyException("это не SOCKS5-прокси")
        when (sel[1].toInt() and 0xFF) {
            0 -> {}
            2 -> {
                if (!auth) throw ProxyException("прокси требует логин и пароль")
                ch.writeAll(authRequest(user, pass))
                val r = ch.readFully(2)
                if (r[1].toInt() != 0) throw ProxyException("прокси не принял логин или пароль")
            }
            0xFF -> throw ProxyException(if (auth) "прокси не принял способ входа" else "прокси требует логин и пароль")
            else -> throw ProxyException("неизвестный способ входа ${sel[1].toInt() and 0xFF}")
        }
    }

    /** Sends a request and reads the reply; returns the BND address. */
    fun command(ch: SocketChannel, cmd: Int, addr: InetAddress, port: Int): InetSocketAddress {
        ch.writeAll(request(cmd, addr, port))
        val head = ch.readFully(4)
        if (head[0].toInt() != 5) throw ProxyException("некорректный ответ прокси")
        val rep = head[1].toInt() and 0xFF
        val bind = readAddress(ch, head[3].toInt() and 0xFF)
        if (rep != 0) throw ProxyException("прокси: ${replyText(rep)}", rep)
        return bind
    }

    private fun readAddress(ch: SocketChannel, atyp: Int): InetSocketAddress {
        val a: InetAddress = when (atyp) {
            1 -> InetAddress.getByAddress(ch.readFully(4))
            4 -> InetAddress.getByAddress(ch.readFully(16))
            3 -> {
                val n = ch.readFully(1)[0].toInt() and 0xFF
                ch.readFully(n) // a domain name in the reply: unusual, treat as unspecified
                InetAddress.getByAddress(ByteArray(4))
            }
            else -> throw ProxyException("некорректный тип адреса в ответе прокси: $atyp")
        }
        val p = ch.readFully(2)
        return InetSocketAddress(a, ((p[0].toInt() and 0xFF) shl 8) or (p[1].toInt() and 0xFF))
    }

    fun connect(ch: SocketChannel, user: String, pass: String, dst: InetSocketAddress) {
        handshake(ch, user, pass)
        command(ch, CMD_CONNECT, dst.address, dst.port)
    }

    /**
     * UDP ASSOCIATE. Returns the relay endpoint to send datagrams to. An unspecified BND address
     * (0.0.0.0 / ::) means "the proxy's own address".
     */
    fun udpAssociate(ch: SocketChannel, user: String, pass: String, proxy: InetSocketAddress): InetSocketAddress {
        handshake(ch, user, pass)
        val any = if (proxy.address is Inet6Address) InetAddress.getByAddress(ByteArray(16)) else InetAddress.getByAddress(ByteArray(4))
        val bind = command(ch, CMD_UDP_ASSOCIATE, any, 0)
        val addr = if (bind.address.isAnyLocalAddress) proxy.address else bind.address
        if (bind.port == 0) throw ProxyException("прокси не сообщил порт для UDP")
        return InetSocketAddress(addr, bind.port)
    }

    /** Header prepended to every datagram sent to the UDP relay. */
    fun udpHeader(dst: InetAddress, port: Int): ByteArray = byteArrayOf(0, 0, 0) + address(dst, port)

    /** Offset of the payload in a datagram received from the relay, or -1 if invalid/fragmented. */
    fun udpPayloadOffset(b: ByteArray, len: Int): Int {
        if (len < 4 || b[2].toInt() != 0) return -1
        val off = when (b[3].toInt() and 0xFF) {
            1 -> 4 + 4 + 2
            4 -> 4 + 16 + 2
            3 -> if (len < 5) return -1 else 4 + 1 + (b[4].toInt() and 0xFF) + 2
            else -> return -1
        }
        return if (off <= len) off else -1
    }
}

/** HTTP proxy with the CONNECT method (TCP only). */
object HttpConnect {
    fun request(dst: InetSocketAddress, user: String, pass: String): ByteArray {
        val a = dst.address
        val hostPort = if (a is Inet6Address) "[${a.hostAddress}]:${dst.port}" else "${a.hostAddress}:${dst.port}"
        val sb = StringBuilder()
        sb.append("CONNECT ").append(hostPort).append(" HTTP/1.1\r\n")
        sb.append("Host: ").append(hostPort).append("\r\n")
        if (user.isNotEmpty()) {
            val token = Base64.getEncoder().encodeToString("$user:$pass".toByteArray(Charsets.UTF_8))
            sb.append("Proxy-Authorization: Basic ").append(token).append("\r\n")
        }
        sb.append("\r\n")
        return sb.toString().toByteArray(Charsets.ISO_8859_1)
    }

    /** Status code from the response head ("HTTP/1.1 200 Connection established"). */
    fun status(head: String): Int {
        val line = head.substringBefore("\r\n")
        if (!line.startsWith("HTTP/")) throw ProxyException("это не HTTP-прокси")
        return line.split(' ').getOrNull(1)?.toIntOrNull() ?: throw ProxyException("некорректный ответ HTTP-прокси")
    }

    fun connect(ch: SocketChannel, user: String, pass: String, dst: InetSocketAddress) {
        ch.writeAll(request(dst, user, pass))
        // Read byte by byte up to the end of the head so no tunnelled data is consumed.
        val sb = StringBuilder()
        val one = ByteBuffer.allocate(1)
        while (!sb.endsWith("\r\n\r\n")) {
            one.clear()
            if (ch.read(one) < 0) throw ProxyException("HTTP-прокси закрыл соединение")
            sb.append((one.get(0).toInt() and 0xFF).toChar())
            if (sb.length > 16384) throw ProxyException("слишком длинный ответ HTTP-прокси")
        }
        val code = status(sb.toString())
        if (code == 407) throw ProxyException("HTTP-прокси требует логин и пароль", code)
        if (code !in 200..299) throw ProxyException("HTTP-прокси ответил $code", code)
    }
}

/** DNS over TCP (RFC 7766): 2-byte length prefix. */
object DnsTcp {
    fun query(ch: SocketChannel, q: ByteArray, off: Int, len: Int): ByteArray {
        val out = ByteArray(2 + len)
        out[0] = (len ushr 8).toByte()
        out[1] = len.toByte()
        System.arraycopy(q, off, out, 2, len)
        ch.writeAll(out)
        val l = ch.readFully(2)
        val n = ((l[0].toInt() and 0xFF) shl 8) or (l[1].toInt() and 0xFF)
        if (n < 12) throw IOException("bad DNS response")
        return ch.readFully(n)
    }
}

fun isLoopback(a: InetAddress): Boolean = a.isLoopbackAddress || (a is Inet4Address && a.address[0].toInt() == 127)
