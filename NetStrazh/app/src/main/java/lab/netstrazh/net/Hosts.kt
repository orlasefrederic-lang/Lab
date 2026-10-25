package lab.netstrazh.net

/** Host-name rules: a rule "example.com" covers the name itself and all its subdomains. */
object Hosts {
    fun normalize(h: String): String = h.trim().trimEnd('.').lowercase()

    /** True when [host] or one of its parent domains is in [own] or [all]. */
    fun blocked(host: String?, own: Set<String>?, all: Set<String>): Boolean {
        if (host.isNullOrEmpty() || (all.isEmpty() && own.isNullOrEmpty())) return false
        var h = normalize(host)
        while (true) {
            if (h in all || (own != null && h in own)) return true
            val dot = h.indexOf('.')
            if (dot < 0) return false
            h = h.substring(dot + 1)
        }
    }
}
