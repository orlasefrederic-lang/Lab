package lab.netstrazh.vpn

import lab.netstrazh.net.withDeadline
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
 *
 * Every wait is bounded by the caller's timeout: the connection is opened on its own thread, and a
 * write that blocks closes the connection. A connection that answers nothing at all while a query
 * times out is considered stalled (e.g. its path through the VPN died silently) and replaced.
 */
class DnsPipe(private val open: () -> SocketChannel) {
    private class Conn(val ch: SocketChannel) {
        val pending = HashMap<Int, CompletableFuture<ByteArray>>()
        val writeLock = Any()
        @Volatile var dead = false
        /** When the last response arrived. */
        @Volatile var lastRx = 0L
    }

    private val lock = Any()
    private var conn: Conn? = null
    private var connecting: CompletableFuture<Conn>? = null
    /** Bumped by [close], so a connection that finishes opening afterwards is discarded. */
    private var generation = 0
    private var nextId = (System.nanoTime() and 0xFFFF).toInt()

    /** Resolves one query (wire format); throws IOException on failure. Blocks up to about [timeoutMs]. */
    fun query(q: ByteArray, off: Int, len: Int, timeoutMs: Long): ByteArray {
        require(len >= 12)
        val origId = ((q[off].toInt() and 0xFF) shl 8) or (q[off + 1].toInt() and 0xFF)
        val deadline = System.currentTimeMillis() + timeoutMs
        var lastError: Exception? = null
        // One retry on a fresh connection: the resolver may have closed an idle pipe.
        repeat(2) {
            val left = deadline - System.currentTimeMillis()
            if (left <= 0) throw IOException("DNS timeout")
            val f = CompletableFuture<ByteArray>()
            var c: Conn? = null
            val sentAt = System.currentTimeMillis()
            try {
                c = connection(left)
                send(c, q, off, len, f, left)
                val r = f.get(maxOf(1L, deadline - System.currentTimeMillis()), TimeUnit.MILLISECONDS)
                r[0] = (origId ushr 8).toByte()
                r[1] = origId.toByte()
                return r
            } catch (e: TimeoutException) {
                val stalled = c != null && synchronized(lock) {
                    c.pending.values.remove(f)
                    c.lastRx < sentAt
                }
                if (stalled) fail(c!!, IOException("DNS pipe stalled"))
                throw IOException("DNS timeout")
            } catch (e: ExecutionException) {
                lastError = e.cause as? Exception ?: e
            } catch (e: IOException) {
                lastError = e
            }
        }
        throw lastError as? IOException ?: IOException(lastError)
    }

    /** The open connection, or one being opened (shared by concurrent queries); waits up to [timeoutMs]. */
    private fun connection(timeoutMs: Long): Conn {
        val f: CompletableFuture<Conn>
        var opener = false
        val gen: Int
        synchronized(lock) {
            conn?.takeIf { !it.dead }?.let { return it }
            gen = generation
            f = connecting ?: CompletableFuture<Conn>().also { connecting = it; opener = true }
        }
        if (opener) thread(name = "ns-dns-open", isDaemon = true) {
            try {
                val c = Conn(open())
                val keep = synchronized(lock) {
                    if (connecting === f) connecting = null
                    if (gen == generation) { conn = c; true } else false
                }
                if (!keep) {
                    try { c.ch.close() } catch (_: Exception) {}
                    f.completeExceptionally(IOException("closed"))
                    return@thread
                }
                thread(name = "ns-dns-pipe", isDaemon = true) { readLoop(c) }
                f.complete(c)
            } catch (e: Exception) {
                synchronized(lock) { if (connecting === f) connecting = null }
                f.completeExceptionally(e)
            }
        }
        return try {
            f.get(timeoutMs, TimeUnit.MILLISECONDS)
        } catch (e: TimeoutException) {
            throw IOException("no DNS connection through the proxy")
        } catch (e: ExecutionException) {
            throw e.cause as? IOException ?: IOException(e.cause)
        }
    }

    private fun send(c: Conn, q: ByteArray, off: Int, len: Int, f: CompletableFuture<ByteArray>, timeoutMs: Long) {
        val frame = ByteArray(2 + len)
        frame[0] = (len ushr 8).toByte()
        frame[1] = len.toByte()
        System.arraycopy(q, off, frame, 2, len)
        val id: Int
        synchronized(lock) {
            if (c.dead) throw IOException("DNS pipe closed")
            var i: Int
            do {
                nextId = (nextId + 1) and 0xFFFF
                i = nextId
            } while (c.pending.containsKey(i))
            id = i
            c.pending[id] = f
        }
        frame[2] = (id ushr 8).toByte()
        frame[3] = id.toByte()
        try {
            // Length and message in one write (RFC 7766 section 8); a write that cannot finish in
            // time means the path is stuck, and closing the channel ends it.
            synchronized(c.writeLock) {
                withDeadline(c.ch, timeoutMs) {
                    val bb = ByteBuffer.wrap(frame)
                    while (bb.hasRemaining()) c.ch.write(bb)
                }
            }
        } catch (e: IOException) {
            synchronized(lock) { c.pending.remove(id) }
            fail(c, e)
            throw e
        }
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
                c.lastRx = System.currentTimeMillis()
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
        // Closing does not need the write lock: it also unblocks a write stuck in progress.
        try { c.ch.close() } catch (_: Exception) {}
        for (f in waiting) f.completeExceptionally(e)
    }

    fun close() {
        val c = synchronized(lock) {
            generation++
            connecting = null
            conn.also { conn = null }
        } ?: return
        fail(c, IOException("closed"))
    }
}
