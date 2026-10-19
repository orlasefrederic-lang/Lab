package lab.netstrazh.vpn

import java.io.IOException
import java.nio.ByteBuffer
import java.nio.channels.SocketChannel
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import kotlin.concurrent.thread

/**
 * One long-lived DNS-over-TCP connection (RFC 7766) to a resolver, opened through the proxy.
 * Queries are pipelined: each gets a unique message ID on the wire, and a reader thread matches
 * responses back by ID and restores the app's original ID. A new proxied connection per lookup would
 * cost a full handshake to the VPN server every time; this keeps lookups at about one round trip.
 */
class DnsPipe(private val open: () -> SocketChannel) {
    private class Conn(val ch: SocketChannel) {
        val pending = HashMap<Int, CompletableFuture<ByteArray>>()
        @Volatile var dead = false
    }

    private val lock = Any()
    private var conn: Conn? = null
    private var nextId = (System.nanoTime() and 0xFFFF).toInt()

    /** Resolves one query (wire format); throws IOException on failure. Blocks up to [timeoutMs]. */
    fun query(q: ByteArray, off: Int, len: Int, timeoutMs: Long): ByteArray {
        require(len >= 12)
        val origId = ((q[off].toInt() and 0xFF) shl 8) or (q[off + 1].toInt() and 0xFF)
        var lastError: Exception? = null
        // One retry on a fresh connection: the resolver may have closed an idle pipe.
        repeat(2) {
            val f = CompletableFuture<ByteArray>()
            try {
                send(q, off, len, f)
                val r = f.get(timeoutMs, TimeUnit.MILLISECONDS)
                r[0] = (origId ushr 8).toByte()
                r[1] = origId.toByte()
                return r
            } catch (e: TimeoutException) {
                synchronized(lock) { conn?.let { c -> c.pending.values.remove(f) } }
                throw IOException("DNS timeout")
            } catch (e: ExecutionException) {
                lastError = e.cause as? Exception ?: e
            } catch (e: IOException) {
                lastError = e
            }
        }
        throw lastError as? IOException ?: IOException(lastError)
    }

    private fun send(q: ByteArray, off: Int, len: Int, f: CompletableFuture<ByteArray>) {
        val frame = ByteArray(2 + len)
        frame[0] = (len ushr 8).toByte()
        frame[1] = len.toByte()
        System.arraycopy(q, off, frame, 2, len)
        synchronized(lock) {
            val c = conn?.takeIf { !it.dead } ?: connect()
            var id: Int
            do {
                nextId = (nextId + 1) and 0xFFFF
                id = nextId
            } while (c.pending.containsKey(id))
            frame[2] = (id ushr 8).toByte()
            frame[3] = id.toByte()
            c.pending[id] = f
            try {
                // Length and message in one write (RFC 7766 section 8).
                val bb = ByteBuffer.wrap(frame)
                while (bb.hasRemaining()) c.ch.write(bb)
            } catch (e: IOException) {
                c.pending.remove(id)
                fail(c, e)
                throw e
            }
        }
    }

    /** Called with [lock] held. */
    private fun connect(): Conn {
        val c = Conn(open())
        conn = c
        thread(name = "ns-dns-pipe", isDaemon = true) { readLoop(c) }
        return c
    }

    private fun readLoop(c: Conn) {
        val head = ByteBuffer.allocate(2)
        try {
            while (true) {
                head.clear()
                readFully(c.ch, head)
                val n = ((head.get(0).toInt() and 0xFF) shl 8) or (head.get(1).toInt() and 0xFF)
                val body = ByteBuffer.allocate(n)
                readFully(c.ch, body)
                val r = body.array()
                if (n < 12) continue
                val id = ((r[0].toInt() and 0xFF) shl 8) or (r[1].toInt() and 0xFF)
                val f = synchronized(lock) { c.pending.remove(id) }
                f?.complete(r)
            }
        } catch (e: IOException) {
            fail(c, e)
        }
    }

    private fun readFully(ch: SocketChannel, bb: ByteBuffer) {
        while (bb.hasRemaining()) {
            if (ch.read(bb) < 0) throw IOException("resolver closed the connection")
        }
    }

    private fun fail(c: Conn, e: IOException) {
        val waiting: List<CompletableFuture<ByteArray>>
        synchronized(lock) {
            c.dead = true
            if (conn === c) conn = null
            waiting = c.pending.values.toList()
            c.pending.clear()
        }
        try { c.ch.close() } catch (_: Exception) {}
        for (f in waiting) f.completeExceptionally(e)
    }

    fun close() {
        val c = synchronized(lock) { conn.also { conn = null } } ?: return
        fail(c, IOException("closed"))
    }
}
