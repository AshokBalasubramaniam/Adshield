package com.adshield.perf

import com.adshield.dns.DnsCache
import com.adshield.dns.DnsParser
import com.adshield.dns.DnsQueryProcessor
import com.adshield.dns.DnsTestUtil
import com.adshield.dns.DnsUpstream
import com.adshield.domain.model.BlockCategory
import com.adshield.domain.model.BlockMode
import com.adshield.engine.AdFilteringEngine
import com.adshield.engine.DomainSet
import com.adshield.engine.RuleSnapshot
import kotlinx.coroutines.runBlocking
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File

/**
 * Micro-benchmark used for the before/after comparison. It only runs when the BENCH_LABEL environment
 * variable is set (so normal test runs stay fast) and writes `build/benchmark/<label>.txt`.
 * It deliberately uses only APIs that exist in both the old and the new code.
 */
class EngineBenchmarkTest {
    // The Android unit-test classpath hides java.lang.management, but the JVM that runs the test has it: use reflection.
    private val bean: Any? = runCatching {
        Class.forName("java.lang.management.ManagementFactory").getMethod("getThreadMXBean").invoke(null)
    }.getOrNull()
    private val allocMethod = runCatching {
        Class.forName("com.sun.management.ThreadMXBean").getMethod("getThreadAllocatedBytes", Long::class.javaPrimitiveType).also { it.isAccessible = true }
    }.getOrNull()

    private fun allocated(): Long = runCatching { allocMethod!!.invoke(bean, Thread.currentThread().id) as Long }.getOrDefault(0L)

    private inline fun measure(name: String, iterations: Int, out: StringBuilder, block: (Int) -> Unit) {
        repeat(iterations / 3) { block(it) } // warm-up (JIT)
        val a0 = allocated(); val t0 = System.nanoTime()
        repeat(iterations) { block(it) }
        val ns = (System.nanoTime() - t0).toDouble() / iterations
        val bytes = (allocated() - a0).toDouble() / iterations
        out.appendLine("%-44s %9.0f ns/op %9.0f B/op".format(name, ns, bytes))
    }

    @Test fun run() {
        val label = System.getenv("BENCH_LABEL")
        assumeTrue(label != null)
        val sb = StringBuilder()
        val ads = DomainSet.Builder(200_000).also { b -> repeat(200_000) { b.add("h$it.ads$it.example") } }.build()
        val engine = AdFilteringEngine().apply { update(RuleSnapshot(categorySets = mapOf(BlockCategory.ADS to ads), loadedAtMillis = 1)) }
        val rawA = DnsTestUtil.query("www.example.com", 1)
        val names = Array(4096) { "cdn$it.static.site$it.example.com" }

        measure("DnsParser.parseQuery", 2_000_000, sb) { DnsParser.parseQuery(rawA) }
        measure("engine.evaluate (miss, 200k rules, cold)", 1_000_000, sb) { engine.evaluate("n$it.sub.site$it.example.com") }
        measure("engine.evaluate (hit, 200k rules)", 1_000_000, sb) { engine.evaluate("x.h${it % 200_000}.ads${it % 200_000}.example") }
        measure("engine.evaluate (repeat, decision cache)", 2_000_000, sb) { engine.evaluate(names[it and 4095]) }

        val events = java.util.concurrent.atomic.AtomicLong()
        val processor = DnsQueryProcessor(engine, DnsCache(), { DnsUpstream { q -> DnsTestUtil.aResponse(q) } }, { BlockMode.NULL_IP }, { events.incrementAndGet() })
        val blockedQ = DnsTestUtil.query("h5.ads5.example", 1)
        val allowedQs = Array(4096) { DnsTestUtil.query(names[it], 1) }
        runBlocking {
            measure("processor: blocked name end-to-end", 500_000, sb) { runBlocking { processor.process(blockedQ, null) } }
            measure("processor: allowed, first resolve (miss)", 200_000, sb) { runBlocking { processor.process(DnsTestUtil.query("m$it.example.org", 1), null) } }
            allowedQs.forEach { processor.process(it, null) }
            measure("processor: allowed, cache hit", 500_000, sb) { runBlocking { processor.process(allowedQs[it and 4095], null) } }
        }
        File("build/benchmark").mkdirs()
        File("build/benchmark/$label.txt").writeText("label=$label  jvm=${System.getProperty("java.version")}  events=${events.get()}\n$sb")
        println(sb)
    }
}
