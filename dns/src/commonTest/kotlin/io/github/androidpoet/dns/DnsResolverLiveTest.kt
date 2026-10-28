package io.github.androidpoet.dns

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeSource

/**
 * Talks to the public resolvers in [Upstreams]. Needs the network; every lookup
 * is for a well-known name whose records are stable.
 */
class DnsResolverLiveTest {
    private val signedName = "example.com"

    @Test
    fun test_lookupIp_overDoh_returnsAddresses() =
        runTest(timeout = 60.seconds) {
            DnsResolver(DnsConfig(upstreams = listOf(Upstreams.Cloudflare.https()))).use { dns ->
                val addresses = dns.lookupIp(signedName)

                assertTrue(addresses.isNotEmpty())
                assertTrue(addresses.all(::isIpLiteral), addresses.toString())
            }
        }

    @Test
    fun test_lookupIp_overDot_returnsAddresses() =
        runTest(timeout = 60.seconds) {
            DnsResolver(DnsConfig(upstreams = listOf(Upstreams.Quad9.tls()))).use { dns ->
                assertTrue(dns.lookupIp(signedName, IpFamily.Ipv4).all { ':' !in it })
                assertTrue(dns.lookupIp(signedName, IpFamily.Ipv6).all { ':' in it })
            }
        }

    @Test
    fun test_lookup_txtAndMx_returnPresentationData() =
        runTest(timeout = 60.seconds) {
            DnsResolver().use { dns ->
                val txt = dns.lookup(signedName, RecordType.TXT)
                val ns = dns.lookup(signedName, RecordType.NS)

                assertTrue(txt.records.all { it.type == RecordType.TXT }, txt.records.toString())
                assertTrue(txt.records.any { it.data.startsWith("v=spf1") }, txt.records.toString())
                assertTrue(ns.records.size >= 2, ns.records.toString())
                assertTrue(ns.records.all { it.name == "$signedName." && it.ttl > 0 })
                assertEquals(DnsSecurity.Unvalidated, txt.security)
            }
        }

    @Test
    fun test_dnssec_validatesASignedNameAndRejectsABogusOne() =
        runTest(timeout = 90.seconds) {
            DnsResolver(DnsConfig(upstreams = listOf(Upstreams.Cloudflare.https()), dnssec = true)).use { dns ->
                assertEquals(DnsSecurity.Secure, dns.lookup(signedName, RecordType.A).security)

                // dnssec-failed.org is deliberately signed with a broken chain. A public
                // resolver validates it itself and answers SERVFAIL (hickory queries with
                // CD=0); an upstream that hands the records over fails local validation.
                val failure = assertFailsWith<DnsException> { dns.lookup("dnssec-failed.org", RecordType.A) }
                assertTrue(failure.kind == DnsErrorKind.Bogus || failure.kind == DnsErrorKind.ServerFailure, failure.toString())
                assertFalse("dnssec-failed" in failure.message.orEmpty(), failure.message)
            }
        }

    @Test
    fun test_lookup_missingName_failsWithNoRecordsAndNeverNamesIt() =
        runTest(timeout = 60.seconds) {
            val name = "this-name-does-not-exist-dns-kmp.invalid"
            DnsResolver().use { dns ->
                val failure = assertFailsWith<DnsException> { dns.lookupIp(name) }

                assertEquals(DnsErrorKind.NoRecords, failure.kind, failure.message)
                assertFalse("dns-kmp" in failure.message.orEmpty(), failure.message)
            }
        }

    @Test
    fun test_lookup_invalidName_failsWithoutTouchingTheNetwork() =
        runTest(timeout = 30.seconds) {
            DnsResolver(blackhole(timeout = 30)).use { dns ->
                val failure = assertFailsWith<DnsException> { dns.lookup("exa mple..com", RecordType.A) }

                assertEquals(DnsErrorKind.InvalidName, failure.kind)
            }
        }

    @Test
    fun test_lookupIp_ipLiteral_isReturnedWithoutAQuery() =
        runTest(timeout = 30.seconds) {
            DnsResolver(blackhole(timeout = 30)).use { dns ->
                assertEquals(listOf("192.0.2.7"), dns.lookupIp("192.0.2.7"))
                assertEquals(listOf("192.0.2.7"), dns.lookupIp("192.0.2.7", IpFamily.Ipv4))
                assertEquals(emptyList(), dns.lookupIp("192.0.2.7", IpFamily.Ipv6))
                assertEquals(listOf("2001:db8::7"), dns.lookupIp("2001:db8::7", IpFamily.Ipv6))
            }
        }

    @Test
    fun test_lookupIp_malformedLiteral_isQueriedNotEchoed() =
        runTest(timeout = 60.seconds) {
            DnsResolver(blackhole(timeout = 1)).use { dns ->
                // A string that merely looks like IPv6 must go to the upstream
                // (and time out here), never come back as an address.
                val failure = assertFailsWith<DnsException> { dns.lookupIp("not::ip") }

                assertTrue(failure.kind in setOf(DnsErrorKind.Timeout, DnsErrorKind.InvalidName), failure.message)
            }
        }

    @Test
    fun test_lookup_unreachableUpstream_timesOutWithTimeout() =
        runTest(timeout = 60.seconds) {
            DnsResolver(blackhole(timeout = 1)).use { dns ->
                val failure = assertFailsWith<DnsException> { dns.lookupIp(signedName) }

                assertEquals(DnsErrorKind.Timeout, failure.kind, failure.message)
            }
        }

    @Test
    fun test_lookup_cancelledCoroutine_returnsAtOnce() =
        realTime {
            DnsResolver(blackhole(timeout = 60)).use { dns ->
                val started = TimeSource.Monotonic.markNow()
                val job = launch { dns.lookupIp(signedName) }
                delay(500)

                job.cancel()
                withTimeout(5.seconds) { job.join() }

                assertTrue(job.isCancelled)
                assertTrue(started.elapsedNow() < 10.seconds)
            }
        }

    @Test
    fun test_close_cancelsRunningLookupsAndRefusesNewOnes() =
        realTime {
            val dns = DnsResolver(blackhole(timeout = 60))
            val running = async { runCatching { dns.lookupIp(signedName) } }
            delay(500)

            dns.close()
            val outcome = withTimeout(5.seconds) { running.await() }

            val failure = outcome.exceptionOrNull()
            assertTrue(failure is DnsException && failure.kind == DnsErrorKind.Closed, failure.toString())
            assertTrue(dns.isClosed)
            val after = assertFailsWith<DnsException> { dns.lookupIp(signedName) }
            assertEquals(DnsErrorKind.Closed, after.kind)
            dns.close() // idempotent
        }

    @Test
    fun test_everyPreset_answersOverDohAndDot() =
        runTest(timeout = 180.seconds) {
            val failures =
                Upstreams.all
                    .flatMap { provider -> listOf(provider.https(), provider.tls()) }
                    .map { upstream ->
                        async {
                            runCatching {
                                DnsResolver(DnsConfig(upstreams = listOf(upstream), timeout = 10.seconds)).use { dns ->
                                    check(dns.lookupIp(signedName, IpFamily.Ipv4).isNotEmpty()) { "no addresses" }
                                }
                            }.exceptionOrNull()?.let { "$upstream: ${it.message}" }
                        }
                    }.awaitAll()
                    .filterNotNull()

            assertTrue(failures.isEmpty(), failures.joinToString("\n"))
        }

    @Test
    fun test_clearCache_thenLookupStillWorks() =
        runTest(timeout = 60.seconds) {
            DnsResolver().use { dns ->
                val first = dns.lookupIp(signedName)
                dns.clearCache()
                val second = dns.lookupIp(signedName)

                // A CDN may rotate the set between two queries; both must be answers.
                assertTrue(first.isNotEmpty() && second.isNotEmpty(), "$first / $second")
                assertTrue(second.all(::isIpLiteral), second.toString())
            }
        }

    @Test
    fun test_cancelledCoroutine_surfacesAsCancellationNotDnsException() =
        realTime {
            DnsResolver(blackhole(timeout = 60)).use { dns ->
                var caught: Throwable? = null
                val job =
                    launch {
                        try {
                            dns.lookupIp(signedName)
                        } catch (error: Throwable) {
                            caught = error
                            throw error
                        }
                    }
                delay(500)
                job.cancel()
                withTimeout(5.seconds) { job.join() }

                assertTrue(caught is CancellationException, caught.toString())
            }
        }

    /** runTest's virtual clock would skip past a blocked native call; these tests need wall time. */
    private fun realTime(block: suspend CoroutineScope.() -> Unit) =
        runTest(timeout = 60.seconds) { withContext(Dispatchers.Default) { block() } }

    /** TEST-NET-1 never answers, so lookups hang until the timeout or a cancel. */
    private fun blackhole(timeout: Int) =
        DnsConfig(
            upstreams = listOf(Upstream.Tls("blackhole.invalid", listOf("192.0.2.1"))),
            timeout = timeout.seconds,
            attempts = 1,
        )
}
