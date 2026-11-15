package lab.netstrazh.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * What a host rule shows as "stopped by it": attempts of the apps it applies to, to the addresses it
 * covers, made since the rule exists. The journal is read in rows cut at the times the rules were
 * made (see Db.stopped), so a row lies wholly before or wholly after any rule's time.
 */
class HostRuleCountTest {
    private val telegram = 10123
    private val browser = 10200

    private fun row(appId: Int, host: String, first: Long, last: Long = first, count: Int = 1) = StoppedRow(appId, host, count, first, last)

    private fun stoppedBy(rule: Rules.HostRule, rows: List<StoppedRow>): Int = rows.filter { rule.counts(it) }.sumOf { it.count }

    @Test
    fun aRuleCountsWhatCameSinceItWasMade() {
        val rule = Rules.HostRule("org.telegram.messenger", "google.com", since = 1_000, appId = telegram)
        assertTrue(rule.counts(row(telegram, "google.com", 1_000)))
        assertTrue(rule.counts(row(telegram, "google.com", 5_000, 9_000, count = 40)))
        assertFalse("before the rule", rule.counts(row(telegram, "google.com", 999)))
    }

    @Test
    fun anAddressBlockedAgainStartsFromNothing() {
        // Blocked at 1000 and hammered 27 times, unblocked, blocked again at 50000: nothing since.
        val journal = listOf(row(telegram, "www.google.com", 1_200, 40_000, count = 27))
        val first = Rules.HostRule("org.telegram.messenger", "google.com", since = 1_000, appId = telegram)
        val again = Rules.HostRule("org.telegram.messenger", "google.com", since = 50_000, appId = telegram)
        assertEquals(27, stoppedBy(first, journal))
        assertEquals("the new rule does not inherit the old attempts", 0, stoppedBy(again, journal))
        // The next attempt is the new rule's first.
        assertEquals(1, stoppedBy(again, journal + row(telegram, "www.google.com", 50_300)))
    }

    @Test
    fun aRuleForAllAppsDoesNotTakeOverWhatAnAppsRuleStoppedBefore() {
        val journal = listOf(
            row(telegram, "google.com", 2_000, 3_000, count = 5), // stopped by Telegram's own rule
            row(telegram, "google.com", 60_000, 61_000, count = 2),
            row(browser, "mail.google.com", 62_000),
        )
        val forAll = Rules.HostRule(Rules.ALL, "google.com", since = 50_000, appId = null)
        assertEquals("only attempts since the general rule exists, of any app", 3, stoppedBy(forAll, journal))
    }

    @Test
    fun anAppsRuleCountsOnlyThatApp() {
        val rule = Rules.HostRule("org.telegram.messenger", "google.com", since = 1_000, appId = telegram)
        assertFalse(rule.counts(row(browser, "google.com", 2_000)))
        // A rule left behind by a removed app (no app id) matches no app's attempts.
        val orphan = Rules.HostRule("gone.app", "google.com", since = 1_000, appId = null)
        assertFalse(orphan.counts(row(telegram, "google.com", 2_000)))
    }

    @Test
    fun subdomainsCountButLookalikesDoNot() {
        val rule = Rules.HostRule(Rules.ALL, "google.com", since = 1_000, appId = null)
        assertTrue(rule.counts(row(browser, "www.google.com", 2_000)))
        assertTrue("the journal may hold the name in another case", rule.counts(row(browser, "WWW.Google.com", 2_000)))
        assertFalse(rule.counts(row(browser, "notgoogle.com", 2_000)))
        assertFalse(rule.counts(row(browser, "google.com.example.org", 2_000)))
    }

    @Test
    fun aRuleFromBeforeTimesWereRecordedCountsAllTheJournalHolds() {
        val old = Rules.HostRule(Rules.ALL, "example.org", since = 0, appId = null)
        assertTrue(old.counts(row(browser, "example.org", 1)))
        assertTrue(old.counts(row(telegram, "a.example.org", 9_999_999)))
    }
}
