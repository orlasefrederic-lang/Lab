package lab.netstrazh.net

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.channels.SocketChannel
import kotlin.concurrent.thread

class SocksTest {
    private val lo = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))

    /** Runs [serve] for one accepted connection and returns the client channel. */
    private fun withServer(serve: (Socket) -> Unit, client: (SocketChannel, InetSocketAddress) -> Unit) {
        val ss = ServerSocket(0, 1, lo)
        var err: Throwable? = null
        val t = thread {
            try {
                ss.accept().use(serve)
            } catch (e: Throwable) {
                err = e
            }
        }
        val addr = InetSocketAddress(lo, ss.localPort)
        SocketChannel.open(addr).use { client(it, addr) }
        t.join(3000)
        ss.close()
        err?.let { throw it }
    }

    private fun DataInputStream.bytes(n: Int) = ByteArray(n).also { readFully(it) }

    @Test fun connectNoAuthExactBytes() {
        val got = ByteArrayOutputStream()
        withServer({ s ->
            val i = DataInputStream(s.getInputStream())
            val o = s.getOutputStream()
            got.write(i.bytes(3))            // 05 01 00
            o.write(byteArrayOf(5, 0))
            got.write(i.bytes(10))           // 05 01 00 01 a b c d p p
            o.write(byteArrayOf(5, 0, 0, 1, 0, 0, 0, 0, 0, 0))
            o.write("hello".toByteArray())   // tunnelled data right after the reply
        }) { ch, _ ->
            Socks5.connect(ch, "", "", InetSocketAddress(InetAddress.getByAddress(byteArrayOf(93, 184.toByte(), 216.toByte(), 34)), 443))
            val bb = ByteBuffer.allocate(5)
            while (bb.hasRemaining()) ch.read(bb)
            assertEquals("hello", String(bb.array()))
        }
        assertArrayEquals(byteArrayOf(5, 1, 0, 5, 1, 0, 1, 93, 184.toByte(), 216.toByte(), 34, 1, 0xBB.toByte()), got.toByteArray())
    }

    @Test fun connectIpv6Request() {
        val a6 = InetAddress.getByName("2001:db8::1")
        val req = Socks5.request(Socks5.CMD_CONNECT, a6, 80)
        assertEquals(4 + 16 + 2, req.size)
        assertEquals(4, req[3].toInt())
        assertEquals(80, ((req[20].toInt() and 0xFF) shl 8) or (req[21].toInt() and 0xFF))
    }

    @Test fun usernamePasswordAuth() {
        withServer({ s ->
            val i = DataInputStream(s.getInputStream())
            val o = s.getOutputStream()
            assertArrayEquals(byteArrayOf(5, 2, 0, 2), i.bytes(4))
            o.write(byteArrayOf(5, 2))
            assertEquals(1, i.read())
            val u = String(i.bytes(i.read()))
            val p = String(i.bytes(i.read()))
            assertEquals("kostya" to "секрет", u to p)
            o.write(byteArrayOf(1, 0))
            i.bytes(10)
            o.write(byteArrayOf(5, 0, 0, 1, 0, 0, 0, 0, 0, 0))
        }) { ch, _ ->
            Socks5.connect(ch, "kostya", "секрет", InetSocketAddress(lo, 80))
        }
    }

    @Test fun refusedReplyCarriesCode() {
        withServer({ s ->
            val i = DataInputStream(s.getInputStream())
            val o = s.getOutputStream()
            i.bytes(3); o.write(byteArrayOf(5, 0))
            i.bytes(10); o.write(byteArrayOf(5, 5, 0, 1, 0, 0, 0, 0, 0, 0))
        }) { ch, _ ->
            try {
                Socks5.connect(ch, "", "", InetSocketAddress(lo, 81))
                fail("expected ProxyException")
            } catch (e: ProxyException) {
                assertEquals(5, e.code)
            }
        }
    }

    @Test fun authRequiredButNotConfigured() {
        withServer({ s ->
            DataInputStream(s.getInputStream()).bytes(3)
            s.getOutputStream().write(byteArrayOf(5, 0xFF.toByte()))
        }) { ch, _ ->
            try {
                Socks5.handshake(ch, "", "")
                fail("expected ProxyException")
            } catch (e: ProxyException) {
                assertTrue(e.message!!.contains("логин"))
            }
        }
    }

    @Test fun udpAssociateUsesProxyAddressForUnspecifiedBind() {
        withServer({ s ->
            val i = DataInputStream(s.getInputStream())
            val o = s.getOutputStream()
            i.bytes(3); o.write(byteArrayOf(5, 0))
            val req = i.bytes(10)
            assertEquals(3, req[1].toInt())                 // UDP ASSOCIATE
            assertArrayEquals(ByteArray(6), req.copyOfRange(4, 10)) // 0.0.0.0:0
            o.write(byteArrayOf(5, 0, 0, 1, 0, 0, 0, 0, 0x30, 0x39)) // bind 0.0.0.0:12345
        }) { ch, addr ->
            val relay = Socks5.udpAssociate(ch, "", "", addr)
            assertEquals(lo, relay.address)
            assertEquals(12345, relay.port)
        }
    }

    @Test fun udpHeaderRoundTrip() {
        val h4 = Socks5.udpHeader(InetAddress.getByAddress(byteArrayOf(8, 8, 8, 8)), 53)
        assertArrayEquals(byteArrayOf(0, 0, 0, 1, 8, 8, 8, 8, 0, 53), h4)
        val dgram = h4 + "abc".toByteArray()
        assertEquals(10, Socks5.udpPayloadOffset(dgram, dgram.size))
        val h6 = Socks5.udpHeader(InetAddress.getByName("2001:db8::2"), 443)
        assertEquals(22, Socks5.udpPayloadOffset(h6 + byteArrayOf(1), h6.size + 1))
        val dom = byteArrayOf(0, 0, 0, 3, 3) + "a.b".toByteArray() + byteArrayOf(0, 53, 7)
        assertEquals(10, Socks5.udpPayloadOffset(dom, dom.size))
        val frag = byteArrayOf(0, 0, 1, 1, 8, 8, 8, 8, 0, 53, 9)
        assertEquals(-1, Socks5.udpPayloadOffset(frag, frag.size))
        assertEquals(-1, Socks5.udpPayloadOffset(h4, 5))
    }

    @Test fun httpConnectDoesNotSwallowTunnelledBytes() {
        val req = ByteArrayOutputStream()
        withServer({ s ->
            val i = s.getInputStream()
            val o = s.getOutputStream()
            val sb = StringBuilder()
            while (!sb.endsWith("\r\n\r\n")) sb.append(i.read().toChar())
            req.write(sb.toString().toByteArray())
            o.write("HTTP/1.1 200 Connection established\r\nProxy-Agent: x\r\n\r\nSSH-2.0-banner".toByteArray())
        }) { ch, _ ->
            HttpConnect.connect(ch, "u", "p", InetSocketAddress(InetAddress.getByAddress(byteArrayOf(1, 2, 3, 4)), 22))
            val bb = ByteBuffer.allocate(14)
            while (bb.hasRemaining()) ch.read(bb)
            assertEquals("SSH-2.0-banner", String(bb.array()))
        }
        val head = String(req.toByteArray())
        assertTrue(head, head.startsWith("CONNECT 1.2.3.4:22 HTTP/1.1\r\nHost: 1.2.3.4:22\r\n"))
        assertTrue(head, head.contains("Proxy-Authorization: Basic dTpw\r\n"))
    }

    @Test fun httpConnectErrors() {
        assertEquals(407, HttpConnect.status("HTTP/1.0 407 Proxy Authentication Required\r\n\r\n"))
        try {
            HttpConnect.status("SSH-2.0\r\n\r\n")
            fail()
        } catch (e: ProxyException) {
        }
        val v6 = String(HttpConnect.request(InetSocketAddress(InetAddress.getByName("2001:db8::5"), 443), "", ""))
        assertTrue(v6, v6.startsWith("CONNECT [2001:db8:0:0:0:0:0:5]:443 HTTP/1.1"))
    }

    @Test fun dnsOverTcpFraming() {
        val q = ByteArray(20) { it.toByte() }
        withServer({ s ->
            val i = DataInputStream(s.getInputStream())
            val len = i.readUnsignedShort()
            val body = i.bytes(len)
            val o = s.getOutputStream()
            o.write(byteArrayOf(0, len.toByte()))
            o.write(body.reversedArray())
        }) { ch, _ ->
            val r = DnsTcp.query(ch, q, 0, q.size)
            assertArrayEquals(q.reversedArray(), r)
        }
    }

    @Test fun deadlineAbortsSilentProxy() {
        val start = System.nanoTime()
        withServer({ s ->
            DataInputStream(s.getInputStream()).bytes(3)
            Thread.sleep(1500) // never answers in time
        }) { ch, _ ->
            try {
                withDeadline(ch, 300) { Socks5.handshake(ch, "", "") }
                fail("expected timeout")
            } catch (e: java.io.IOException) {
                assertTrue(e.message, e.message!!.contains("timeout"))
            }
        }
        assertTrue((System.nanoTime() - start) / 1_000_000 < 3000)
    }
}
