package lab.netstrazh

import java.io.Closeable
import java.io.DataInputStream
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicReference

/**
 * Tiny SOCKS5 server (CONNECT + UDP ASSOCIATE, no auth) for end-to-end tests. It runs inside the app
 * process, so its outgoing sockets must be protected from the VPN just like the engine's.
 */
class TestSocks(
    private val protectTcp: (Socket) -> Boolean,
    private val protectUdp: (DatagramSocket) -> Boolean,
    /** Resolves names sent as ATYP 3 (outside our own VPN). */
    private val resolve: (String) -> InetAddress,
) : Closeable {
    private val lo = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
    private val server = ServerSocket(0, 64, lo)
    private val pool = Executors.newCachedThreadPool()
    val port: Int get() = server.localPort
    val connects = CopyOnWriteArrayList<String>()
    val udp = CopyOnWriteArrayList<String>()

    init {
        pool.execute {
            while (!server.isClosed) {
                val c = try { server.accept() } catch (e: IOException) { break }
                pool.execute { handle(c) }
            }
        }
    }

    private fun handle(c: Socket) {
        try {
            val i = DataInputStream(c.getInputStream())
            val o = c.getOutputStream()
            i.readUnsignedByte()
            i.skipBytes(i.readUnsignedByte())
            o.write(byteArrayOf(5, 0))
            i.readUnsignedByte()
            val cmd = i.readUnsignedByte()
            i.readUnsignedByte()
            var name: String? = null
            val addr = when (i.readUnsignedByte()) {
                1 -> InetAddress.getByAddress(ByteArray(4).also { i.readFully(it) })
                4 -> InetAddress.getByAddress(ByteArray(16).also { i.readFully(it) })
                3 -> {
                    name = String(ByteArray(i.readUnsignedByte()).also { i.readFully(it) }, Charsets.US_ASCII)
                    null
                }
                else -> throw IOException("unsupported atyp")
            }
            val port = i.readUnsignedShort()
            when (cmd) {
                1 -> {
                    connects += "${name ?: addr!!.hostAddress}:$port"
                    val target = addr ?: resolve(name!!)
                    val out = java.nio.channels.SocketChannel.open()
                    protectTcp(out.socket())
                    out.socket().connect(InetSocketAddress(target, port), 10_000)
                    o.write(byteArrayOf(5, 0, 0, 1, 0, 0, 0, 0, 0, 0))
                    val s = out.socket()
                    pool.execute { copy(s, c) }
                    copy(c, s)
                    s.close()
                }
                3 -> associate(c, i, o)
                else -> o.write(byteArrayOf(5, 7, 0, 1, 0, 0, 0, 0, 0, 0))
            }
        } catch (_: Exception) {
        } finally {
            try { c.close() } catch (_: Exception) {}
        }
    }

    private fun associate(c: Socket, i: DataInputStream, o: java.io.OutputStream) {
        val relay = DatagramSocket(0, lo)
        val ext = DatagramSocket()
        protectUdp(ext)
        val p = relay.localPort
        o.write(byteArrayOf(5, 0, 0, 1, 0, 0, 0, 0, (p ushr 8).toByte(), p.toByte()))
        val client = AtomicReference<InetSocketAddress?>()
        pool.execute {
            val b = ByteArray(65535)
            try {
                while (true) {
                    val d = DatagramPacket(b, b.size)
                    relay.receive(d)
                    client.set(InetSocketAddress(d.address, d.port))
                    if (d.length < 10 || b[3].toInt() != 1) continue
                    val dst = InetAddress.getByAddress(b.copyOfRange(4, 8))
                    val dport = ((b[8].toInt() and 0xFF) shl 8) or (b[9].toInt() and 0xFF)
                    udp += "${dst.hostAddress}:$dport"
                    ext.send(DatagramPacket(b, 10, d.length - 10, dst, dport))
                }
            } catch (_: Exception) {
            }
        }
        pool.execute {
            val b = ByteArray(65535)
            try {
                while (true) {
                    val d = DatagramPacket(b, 10, b.size - 10)
                    ext.receive(d)
                    val a = d.address.address
                    if (a.size != 4) continue
                    b[0] = 0; b[1] = 0; b[2] = 0; b[3] = 1
                    System.arraycopy(a, 0, b, 4, 4)
                    b[8] = (d.port ushr 8).toByte(); b[9] = d.port.toByte()
                    val to = client.get() ?: continue
                    relay.send(DatagramPacket(b, 0, 10 + d.length, to))
                }
            } catch (_: Exception) {
            }
        }
        // The association lives as long as the control connection.
        while (i.read() >= 0) {}
        relay.close()
        ext.close()
    }

    private fun copy(from: Socket, to: Socket) {
        try {
            val b = ByteArray(16384)
            val inp = from.getInputStream()
            val out = to.getOutputStream()
            while (true) {
                val n = inp.read(b)
                if (n < 0) break
                out.write(b, 0, n)
            }
            to.shutdownOutput()
        } catch (_: Exception) {
            try { to.close() } catch (_: Exception) {}
        }
    }

    override fun close() {
        try { server.close() } catch (_: Exception) {}
        pool.shutdownNow()
    }
}
