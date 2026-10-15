package lab.netstrazh.data

import android.content.ContentValues
import android.content.Context
import android.database.Cursor
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import android.util.Log
import lab.netstrazh.Prefs
import lab.netstrazh.vpn.Conn
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class LogRow(
    val ts: Long,
    val te: Long,
    val uid: Int,
    val proto: String,
    val ip: String,
    val port: Int,
    val host: String?,
    val tx: Long,
    val rx: Long,
    val blocked: Boolean,
    val net: String,
    val active: Boolean = false,
)

class DestRow(
    val host: String?,
    val ip: String,
    val port: Int,
    val proto: String,
    val count: Int,
    val tx: Long,
    val rx: Long,
    val last: Long,
    val blocked: Int,
)

/** Connection journal stored in SQLite. Writes are batched on a background thread. */
class Db private constructor(ctx: Context) : SQLiteOpenHelper(ctx, "netstrazh.db", null, 1) {
    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL(
            "CREATE TABLE conn(id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, te INTEGER, uid INTEGER, " +
                "proto TEXT, ip TEXT, port INTEGER, host TEXT, tx INTEGER, rx INTEGER, blocked INTEGER, net TEXT)"
        )
        db.execSQL("CREATE INDEX conn_ts ON conn(ts)")
        db.execSQL("CREATE INDEX conn_uid ON conn(uid, ts)")
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {}

    companion object {
        private lateinit var helper: Db
        private val queue = ConcurrentLinkedQueue<Conn>()
        private val exec = Executors.newSingleThreadScheduledExecutor { r -> Thread(r, "ns-db").apply { isDaemon = true } }

        fun init(ctx: Context) {
            helper = Db(ctx.applicationContext)
            exec.scheduleWithFixedDelay({ flush() }, 2, 2, TimeUnit.SECONDS)
        }

        fun log(c: Conn) {
            queue.add(c)
        }

        private fun flush() {
            if (queue.isEmpty()) return
            try {
                val db = helper.writableDatabase
                db.beginTransaction()
                try {
                    while (true) {
                        val c = queue.poll() ?: break
                        val v = ContentValues(11)
                        v.put("ts", c.start)
                        v.put("te", if (c.end == 0L) System.currentTimeMillis() else c.end)
                        v.put("uid", c.uid)
                        v.put("proto", c.proto)
                        v.put("ip", c.ip)
                        v.put("port", c.port)
                        v.put("host", c.host)
                        v.put("tx", c.tx)
                        v.put("rx", c.rx)
                        v.put("blocked", if (c.blocked) 1 else 0)
                        v.put("net", c.net)
                        db.insert("conn", null, v)
                    }
                    db.setTransactionSuccessful()
                } finally {
                    db.endTransaction()
                }
            } catch (e: Exception) {
                Log.w("NetStrazh", "db flush", e)
            }
        }

        fun pruneAsync() {
            exec.execute {
                try {
                    val cutoff = System.currentTimeMillis() - Prefs.logDays * 86_400_000L
                    helper.writableDatabase.delete("conn", "ts < ?", arrayOf(cutoff.toString()))
                } catch (_: Exception) {
                }
            }
        }

        fun clear() {
            exec.submit {
                queue.clear()
                helper.writableDatabase.delete("conn", null, null)
            }.get()
        }

        /** Makes sure queued rows are visible to the next query. */
        fun sync() {
            try { exec.submit { flush() }.get(3, TimeUnit.SECONDS) } catch (_: Exception) {}
        }

        const val F_ALL = 0
        const val F_BLOCKED = 1
        const val F_DNS = 2
        const val F_CONN = 3

        fun recent(filter: Int, uids: Collection<Int>?, text: String?, limit: Int = 400): List<LogRow> {
            sync()
            val where = ArrayList<String>()
            val args = ArrayList<String>()
            when (filter) {
                F_BLOCKED -> where += "blocked = 1"
                F_DNS -> where += "proto = 'DNS'"
                F_CONN -> where += "proto != 'DNS'"
            }
            val textCond = if (!text.isNullOrBlank()) {
                args += "%${text.trim()}%"
                args += "%${text.trim()}%"
                "(host LIKE ? OR ip LIKE ?)"
            } else null
            val uidCond = if (uids != null && uids.isNotEmpty()) "uid IN (${uids.joinToString(",")})" else null
            when {
                textCond != null && uidCond != null -> where += "($textCond OR $uidCond)"
                textCond != null -> where += textCond
                uidCond != null -> where += uidCond
            }
            val sql = "SELECT ts, te, uid, proto, ip, port, host, tx, rx, blocked, net FROM conn" +
                (if (where.isEmpty()) "" else " WHERE " + where.joinToString(" AND ")) +
                " ORDER BY ts DESC LIMIT $limit"
            return query(sql, args.toTypedArray()) { c ->
                LogRow(c.getLong(0), c.getLong(1), c.getInt(2), c.getString(3), c.getString(4) ?: "",
                    c.getInt(5), c.getString(6), c.getLong(7), c.getLong(8), c.getInt(9) != 0, c.getString(10) ?: "")
            }
        }

        fun recentForUid(uid: Int, limit: Int = 100): List<LogRow> {
            sync()
            return query(
                "SELECT ts, te, uid, proto, ip, port, host, tx, rx, blocked, net FROM conn WHERE uid = ? ORDER BY ts DESC LIMIT $limit",
                arrayOf(uid.toString())
            ) { c ->
                LogRow(c.getLong(0), c.getLong(1), c.getInt(2), c.getString(3), c.getString(4) ?: "",
                    c.getInt(5), c.getString(6), c.getLong(7), c.getLong(8), c.getInt(9) != 0, c.getString(10) ?: "")
            }
        }

        /** Where an app connected to, grouped by host (or IP when the host is unknown). */
        fun destinations(uid: Int, limit: Int = 200): List<DestRow> {
            sync()
            val sql = "SELECT MAX(host), MAX(ip), port, proto, COUNT(*), SUM(tx), SUM(rx), MAX(ts), SUM(blocked) FROM conn " +
                "WHERE uid = ? AND proto != 'DNS' " +
                "GROUP BY CASE WHEN host IS NULL OR host = '' THEN ip ELSE host END, port, proto " +
                "ORDER BY SUM(tx) + SUM(rx) DESC, MAX(ts) DESC LIMIT $limit"
            return query(sql, arrayOf(uid.toString())) { c ->
                DestRow(c.getString(0), c.getString(1) ?: "", c.getInt(2), c.getString(3), c.getInt(4),
                    c.getLong(5), c.getLong(6), c.getLong(7), c.getInt(8))
            }
        }

        /** Domain names an app looked up. */
        fun dnsNames(uid: Int, limit: Int = 200): List<DestRow> {
            sync()
            val sql = "SELECT host, MAX(ip), 53, 'DNS', COUNT(*), SUM(tx), SUM(rx), MAX(ts), 0 FROM conn " +
                "WHERE uid = ? AND proto = 'DNS' AND host IS NOT NULL GROUP BY host ORDER BY MAX(ts) DESC LIMIT $limit"
            return query(sql, arrayOf(uid.toString())) { c ->
                DestRow(c.getString(0), c.getString(1) ?: "", c.getInt(2), c.getString(3), c.getInt(4),
                    c.getLong(5), c.getLong(6), c.getLong(7), c.getInt(8))
            }
        }

        private fun <T> query(sql: String, args: Array<String>, map: (Cursor) -> T): List<T> {
            val out = ArrayList<T>()
            try {
                helper.readableDatabase.rawQuery(sql, args).use { c ->
                    while (c.moveToNext()) out += map(c)
                }
            } catch (e: Exception) {
                Log.w("NetStrazh", "db query", e)
            }
            return out
        }
    }
}
