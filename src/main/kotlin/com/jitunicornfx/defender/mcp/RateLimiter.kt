package com.jitunicornfx.defender.mcp

import kotlinx.coroutines.delay
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/** One rate rule: at most [permits] acquisitions in any rolling [windowMillis]. */
data class RateRule(val permits: Int, val windowMillis: Long) {
    init {
        require(permits > 0) { "permits must be positive" }
        require(windowMillis > 0) { "windowMillis must be positive" }
    }
}

/**
 * Coroutine-friendly sliding-window rate limiter.
 *
 * [acquire] suspends (never blocks a thread) until every [RateRule] has room, then records the call.
 * Waiters are served in order by the [Mutex], so a burst of tool calls drains at the permitted pace
 * instead of hammering the API into 429s. [clock] and [sleep] are injectable so tests run on virtual
 * time.
 */
class SlidingWindowRateLimiter(
    rules: List<RateRule>,
    private val clock: () -> Long = System::currentTimeMillis,
    private val sleep: suspend (Long) -> Unit = { delay(it) },
) {
    private val rules = rules.sortedBy { it.windowMillis }
    private val longestWindow = this.rules.maxOfOrNull { it.windowMillis } ?: 0L
    private val maxPermits = this.rules.maxOfOrNull { it.permits } ?: 0
    private val history = ArrayDeque<Long>()
    private val mutex = Mutex()

    init {
        require(rules.isNotEmpty()) { "at least one rule is required" }
    }

    /** Suspend until a permit is available under every rule, then take it. */
    suspend fun acquire() {
        mutex.withLock {
            while (true) {
                val now = clock()
                prune(now)
                val wait = waitMillis(now)
                if (wait <= 0) {
                    history.addLast(now)
                    return
                }
                sleep(wait)
            }
        }
    }

    /** Milliseconds until a permit would be available, 0 if one is available now. */
    internal fun waitMillis(now: Long): Long {
        var wait = 0L
        for (rule in rules) {
            val start = now - rule.windowMillis
            val inWindow = history.count { it > start }
            if (inWindow >= rule.permits) {
                // The oldest call that still counts against this rule must age out first.
                val blocking = history.filter { it > start }[inWindow - rule.permits]
                wait = maxOf(wait, blocking - start)
            }
        }
        return wait
    }

    private fun prune(now: Long) {
        while (history.isNotEmpty() && (history.first() <= now - longestWindow || history.size > maxPermits)) {
            history.removeFirst()
        }
    }

    /** Calls recorded within the longest window; for tests and diagnostics. */
    internal fun recorded(): Int = history.size

    companion object {
        /** Defender for Endpoint's general limit: 100 calls per minute and 1500 per hour. */
        fun defenderDefault(clock: () -> Long = System::currentTimeMillis, sleep: suspend (Long) -> Unit = { delay(it) }) =
            SlidingWindowRateLimiter(listOf(RateRule(100, 60_000), RateRule(1_500, 3_600_000)), clock, sleep)

        /** Advanced hunting: 45 calls per minute and 1500 per hour. */
        fun advancedHunting(clock: () -> Long = System::currentTimeMillis, sleep: suspend (Long) -> Unit = { delay(it) }) =
            SlidingWindowRateLimiter(listOf(RateRule(45, 60_000), RateRule(1_500, 3_600_000)), clock, sleep)
    }
}

/**
 * Brake on state-changing calls: at most [maxPerWindow] in any rolling [windowMillis]. Unlike the
 * API limiter it refuses instead of waiting, because a burst of isolations or offboardings is the
 * signature of a hijacked agent, and the right response is to stop, not to pace it.
 */
class ActionBudget(
    private val maxPerWindow: Int,
    private val windowMillis: Long = 3_600_000,
    private val clock: () -> Long = System::currentTimeMillis,
) {
    /** One taken permit; identity matters, so concurrent callers each release their own. */
    class Permit internal constructor(internal val at: Long)

    private val history = ArrayList<Permit>()

    /** Take one action permit; null when the budget is exhausted. */
    @Synchronized
    fun tryAcquire(): Permit? {
        val now = clock()
        history.removeAll { it.at <= now - windowMillis }
        if (history.size >= maxPerWindow) return null
        return Permit(now).also { history += it }
    }

    /**
     * Give back [permit], taken for an action that never reached the API (declined, failed). Only
     * that exact permit is removed, so overlapping approvals cannot release each other's.
     */
    @Synchronized
    fun release(permit: Permit) {
        history.removeAll { it === permit }
    }

    @Synchronized
    fun used(): Int {
        val now = clock()
        return history.count { it.at > now - windowMillis }
    }

    val limit: Int get() = maxPerWindow
}
