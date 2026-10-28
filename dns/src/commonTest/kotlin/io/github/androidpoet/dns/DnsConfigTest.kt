package io.github.androidpoet.dns

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.microseconds
import kotlin.time.Duration.Companion.seconds

class DnsConfigTest {
    @Test
    fun test_settingsJson_carriesEveryField() {
        val config =
            DnsConfig(
                upstreams = listOf(Upstream.Https("doh.example.org", listOf("203.0.113.5"), path = "/q", port = 8443)),
                dnssec = true,
                timeout = 2.seconds,
                attempts = 3,
                cacheSize = 0,
                ipFamily = IpFamily.Ipv6,
            )

        val json = config.settingsJson()

        assertEquals(
            """{"upstreams":[{"protocol":"https","serverName":"doh.example.org","addresses":["203.0.113.5"],"path":"/q","port":8443}],""" +
                """"dnssec":true,"timeoutMs":2000,"attempts":3,"cacheSize":0,"ipFamily":"ipv6"}""",
            json,
        )
    }

    @Test
    fun test_settingsJson_defaultsToCloudflareDohWithoutValidation() {
        val json = DnsConfig().settingsJson()

        assertTrue(json.startsWith("""{"upstreams":[{"protocol":"https","serverName":"cloudflare-dns.com","""), json)
        assertTrue(""""dnssec":false""" in json, json)
        assertTrue(""""ipFamily":"both"""" in json, json)
    }

    @Test
    fun test_settingsJson_plainUpstreamHasNoServerName() {
        val json = DnsConfig(upstreams = listOf(Upstream.Plain(listOf("192.0.2.53")))).settingsJson()

        assertTrue(""""protocol":"plain","serverName":"","addresses":["192.0.2.53"],"port":53""" in json, json)
    }

    @Test
    fun test_init_rejectsEmptyUpstreams() {
        assertFailsWith<IllegalArgumentException> { DnsConfig(upstreams = emptyList()) }
    }

    @Test
    fun test_init_rejectsPlainMixedWithEncrypted() {
        assertFailsWith<IllegalArgumentException> {
            DnsConfig(upstreams = listOf(Upstreams.Quad9.tls(), Upstream.Plain(listOf("192.0.2.53"))))
        }
        // All plain is allowed; so is all encrypted.
        DnsConfig(upstreams = listOf(Upstream.Plain(listOf("192.0.2.53")), Upstream.Plain(listOf("192.0.2.54"))))
        DnsConfig(upstreams = listOf(Upstreams.Quad9.tls(), Upstreams.Cloudflare.https()))
    }

    @Test
    fun test_init_rejectsSubMillisecondTimeout() {
        assertFailsWith<IllegalArgumentException> { DnsConfig(timeout = 500.microseconds) }
    }

    @Test
    fun test_valueSemantics_configAndUpstreams() {
        assertEquals(DnsConfig(dnssec = true), DnsConfig(dnssec = true))
        assertEquals(DnsConfig(dnssec = true).hashCode(), DnsConfig(dnssec = true).hashCode())
        assertTrue(DnsConfig(dnssec = true) != DnsConfig(dnssec = false))
        assertEquals(Upstreams.Quad9.tls(), Upstreams.Quad9.tls())
        assertTrue(Upstreams.Quad9.tls() != Upstreams.Quad9.https())
        assertTrue(Upstream.Plain(listOf("1.1.1.1")) != Upstream.Plain(listOf("1.1.1.1"), port = 5353))
        assertTrue("timeout=5s" in DnsConfig().toString())
    }

    @Test
    fun test_init_rejectsZeroAttemptsAndNegativeCache() {
        assertFailsWith<IllegalArgumentException> { DnsConfig(attempts = 0) }
        assertFailsWith<IllegalArgumentException> { DnsConfig(cacheSize = -1) }
        assertFailsWith<IllegalArgumentException> { DnsConfig(timeout = 0.seconds) }
    }

    @Test
    fun test_jsonQuoted_escapesControlCharactersQuotesAndBackslashes() {
        assertEquals("\"a\\\"b\\\\c\\u0001\"", "a\"b\\c\u0001".jsonQuoted())
    }
}
