package com.jitunicornfx.defender.mcp

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldContainExactly
import io.kotest.matchers.longs.shouldBeGreaterThanOrEqual
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.property.Arb
import io.kotest.property.arbitrary.int
import io.kotest.property.arbitrary.long
import io.kotest.property.checkAll
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.test.currentTime
import kotlinx.coroutines.test.runTest
import java.util.Collections
import java.util.concurrent.atomic.AtomicLong

/** A virtual clock whose sleep advances time, recording every requested wait. */
private class VirtualTime(start: Long = 0) {
    val now = AtomicLong(start)
    val sleeps: MutableList<Long> = Collections.synchronizedList(mutableListOf())
    val clock: () -> Long = { now.get() }
    val sleep: suspend (Long) -> Unit = { ms -> sleeps += ms; now.addAndGet(ms) }
}

class RateLimiterSpec : FunSpec({

    context("RateRule validation") {
        test("permits and window must be positive") {
            shouldThrow<IllegalArgumentException> { RateRule(0, 1) }.message shouldContain "permits"
            shouldThrow<IllegalArgumentException> { RateRule(-3, 1) }.message shouldContain "permits"
            shouldThrow<IllegalArgumentException> { RateRule(1, 0) }.message shouldContain "windowMillis"
            shouldThrow<IllegalArgumentException> { RateRule(1, -1) }.message shouldContain "windowMillis"
            RateRule(1, 1).permits shouldBe 1
        }

        test("any non-positive permits is rejected (property)") {
            checkAll(Arb.int(Int.MIN_VALUE..0), Arb.long(1L..Long.MAX_VALUE)) { p, w ->
                shouldThrow<IllegalArgumentException> { RateRule(p, w) }
            }
        }

        test("a limiter needs at least one rule") {
            shouldThrow<IllegalArgumentException> { SlidingWindowRateLimiter(emptyList()) }.message shouldContain "at least one rule"
        }
    }

    context("SlidingWindowRateLimiter") {
        test("permits up to the limit without waiting, then waits exactly until the oldest call ages out") {
            val t = VirtualTime()
            val limiter = SlidingWindowRateLimiter(listOf(RateRule(2, 1_000)), t.clock, t.sleep)
            limiter.acquire()
            limiter.acquire()
            t.sleeps.shouldBeEmpty()
            limiter.recorded() shouldBe 2
            limiter.acquire()
            t.sleeps shouldContainExactly listOf(1_000L)
            t.now.get() shouldBe 1_000
            // The two calls at t=0 aged out of the window and were pruned.
            limiter.recorded() shouldBe 1
        }

        test("waitMillis reports the remaining time of a partially elapsed window") {
            val t = VirtualTime()
            val limiter = SlidingWindowRateLimiter(listOf(RateRule(1, 1_000)), t.clock, t.sleep)
            limiter.waitMillis(0) shouldBe 0
            limiter.acquire()
            limiter.waitMillis(250) shouldBe 750
            limiter.waitMillis(999) shouldBe 1
            limiter.waitMillis(1_000) shouldBe 0
        }

        test("the most restrictive of several rules decides the wait") {
            val t = VirtualTime()
            val limiter = SlidingWindowRateLimiter(listOf(RateRule(3, 10_000), RateRule(2, 1_000)), t.clock, t.sleep)
            repeat(3) { limiter.acquire() }
            t.sleeps shouldContainExactly listOf(1_000L)
            limiter.acquire()
            // Short rule has room; the long rule (3 per 10s) blocks until the first t=0 call ages out.
            t.sleeps shouldContainExactly listOf(1_000L, 9_000L)
            t.now.get() shouldBe 10_000
        }

        test("calls spaced beyond the window never wait") {
            val t = VirtualTime()
            val limiter = SlidingWindowRateLimiter(listOf(RateRule(1, 100)), t.clock, t.sleep)
            repeat(10) {
                limiter.acquire()
                t.now.addAndGet(100)
            }
            t.sleeps.shouldBeEmpty()
            limiter.recorded() shouldBe 1
        }

        test("for any rule, permits+1 calls at one instant wait exactly one window (property)") {
            checkAll(50, Arb.int(1..50), Arb.long(1L..1_000_000L)) { permits, window ->
                val t = VirtualTime(1_000_000)
                val limiter = SlidingWindowRateLimiter(listOf(RateRule(permits, window)), t.clock, t.sleep)
                repeat(permits) { limiter.acquire() }
                t.sleeps.shouldBeEmpty()
                limiter.acquire()
                t.sleeps shouldContainExactly listOf(window)
            }
        }

        test("defenderDefault allows 100 per minute then waits a minute") {
            val t = VirtualTime()
            val limiter = SlidingWindowRateLimiter.defenderDefault(t.clock, t.sleep)
            repeat(100) { limiter.acquire() }
            t.sleeps.shouldBeEmpty()
            limiter.acquire()
            t.sleeps shouldContainExactly listOf(60_000L)
        }

        test("defenderDefault enforces 1500 per hour") {
            val t = VirtualTime()
            val limiter = SlidingWindowRateLimiter.defenderDefault(t.clock, t.sleep)
            repeat(1_500) { limiter.acquire() }
            t.now.get() shouldBe 14 * 60_000L // 15 batches of 100 separated by 14 one-minute waits
            limiter.acquire()
            t.now.get() shouldBeGreaterThanOrEqual 3_600_000L
        }

        test("advancedHunting allows 45 per minute then waits a minute") {
            val t = VirtualTime()
            val limiter = SlidingWindowRateLimiter.advancedHunting(t.clock, t.sleep)
            repeat(45) { limiter.acquire() }
            t.sleeps.shouldBeEmpty()
            limiter.acquire()
            t.sleeps shouldContainExactly listOf(60_000L)
        }

        test("factories and constructor work with default clock and sleep") {
            SlidingWindowRateLimiter.defenderDefault().acquire()
            SlidingWindowRateLimiter.advancedHunting().acquire()
            val limiter = SlidingWindowRateLimiter(listOf(RateRule(5, 60_000)))
            limiter.acquire()
            limiter.recorded() shouldBe 1
        }

        test("default sleep suspends on virtual time with the coroutine delay") {
            runTest {
                val limiter = SlidingWindowRateLimiter(listOf(RateRule(1, 5_000)), clock = { currentTime })
                limiter.acquire()
                limiter.acquire()
                currentTime shouldBe 5_000
            }
        }

        test("factory default sleeps also suspend on virtual time") {
            runTest {
                val hunting = SlidingWindowRateLimiter.advancedHunting(clock = { currentTime })
                repeat(46) { hunting.acquire() }
                currentTime shouldBe 60_000
                val general = SlidingWindowRateLimiter.defenderDefault(clock = { currentTime })
                repeat(101) { general.acquire() }
                currentTime shouldBe 120_000
            }
        }

        test("rules with equal windows or a stricter long window are both enforced") {
            val t = VirtualTime()
            val limiter = SlidingWindowRateLimiter(listOf(RateRule(1, 1_000), RateRule(3, 1_000)), t.clock, t.sleep)
            limiter.acquire()
            limiter.acquire()
            t.sleeps shouldContainExactly listOf(1_000L)

            val t2 = VirtualTime()
            val l2 = SlidingWindowRateLimiter(listOf(RateRule(5, 1_000), RateRule(2, 10_000)), t2.clock, t2.sleep)
            repeat(3) { l2.acquire() }
            t2.sleeps shouldContainExactly listOf(10_000L)
            l2.recorded() shouldBe 1
        }

        test("concurrent acquirers are serialized and never exceed the rule") {
            val t = VirtualTime()
            val limiter = SlidingWindowRateLimiter(listOf(RateRule(5, 1_000)), t.clock, t.sleep)
            coroutineScope {
                (1..20).map { async(Dispatchers.Default) { limiter.acquire() } }.awaitAll()
            }
            // 20 calls at 5 per second: three full-window waits, never more.
            t.sleeps shouldContainExactly listOf(1_000L, 1_000L, 1_000L)
            t.now.get() shouldBe 3_000
            limiter.recorded() shouldBe 5
        }
    }

    context("ActionBudget") {
        test("grants up to the limit then refuses") {
            val budget = ActionBudget(3, 1_000) { 0 }
            budget.limit shouldBe 3
            List(3) { budget.take() } shouldContainExactly listOf(true, true, true)
            budget.take() shouldBe false
            budget.used() shouldBe 3
        }

        test("release gives back exactly the caller's own permit") {
            var now = 0L
            val budget = ActionBudget(2, 1_000) { now }
            val a = budget.tryAcquire()!!
            now = 900
            budget.tryAcquire()!!
            budget.take() shouldBe false
            // A was declined: releasing it must free A's slot, not the newer B's.
            budget.release(a)
            budget.used() shouldBe 1
            now = 1_000
            // B (taken at 900) still counts until 1900; A's slot was the one freed.
            budget.used() shouldBe 1
            budget.take() shouldBe true
            budget.take() shouldBe false
        }

        test("releasing a permit twice or a stale permit is a no-op") {
            val budget = ActionBudget(1, 1_000) { 0 }
            val p = budget.tryAcquire()!!
            budget.release(p)
            budget.release(p)
            budget.used() shouldBe 0
            budget.take() shouldBe true
            budget.take() shouldBe false
        }

        test("permits age out after the window") {
            var now = 0L
            val budget = ActionBudget(2, 1_000) { now }
            budget.take() shouldBe true
            now = 500
            budget.take() shouldBe true
            budget.take() shouldBe false
            now = 999
            budget.used() shouldBe 2
            now = 1_000
            budget.used() shouldBe 1
            budget.take() shouldBe true
            budget.take() shouldBe false
            now = 2_500
            budget.used() shouldBe 0
        }

        test("a zero budget refuses every action") {
            val budget = ActionBudget(0)
            budget.take() shouldBe false
            budget.used() shouldBe 0
            budget.limit shouldBe 0
        }

        test("never grants more than the limit under concurrency") {
            val budget = ActionBudget(10, 3_600_000) { 42 }
            val granted = coroutineScope {
                (1..200).map { async(Dispatchers.Default) { budget.take() } }.awaitAll()
            }
            granted.count { it } shouldBe 10
            budget.used() shouldBe 10
        }

        test("for any limit, exactly limit acquisitions succeed at one instant (property)") {
            checkAll(Arb.int(0..100)) { limit ->
                val budget = ActionBudget(limit, 1_000) { 7 }
                val results = List(limit + 5) { budget.take() }
                results.count { it } shouldBe limit
            }
        }
    }
})

private fun ActionBudget.take(): Boolean = tryAcquire() != null
