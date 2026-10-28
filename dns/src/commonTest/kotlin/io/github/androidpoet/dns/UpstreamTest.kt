package io.github.androidpoet.dns

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class UpstreamTest {
    @Test
    fun test_isIpLiteral_acceptsV4AndV6() {
        assertTrue(isIpLiteral("1.1.1.1"))
        assertTrue(isIpLiteral("2606:4700:4700::1111"))
        assertTrue(isIpLiteral("::1"))
        assertTrue(isIpLiteral("::ffff:192.0.2.1"))
        assertTrue(isIpLiteral("1:2:3:4:5:6:7:8"))
        assertTrue(isIpLiteral("fe80::1"))
        assertTrue(isIpLiteral("2001:DB8::ABCD"))
        assertTrue(isIpLiteral("::"))
    }

    @Test
    fun test_isIpLiteral_rejectsNamesAndJunk() {
        assertFalse(isIpLiteral("cloudflare-dns.com"))
        assertFalse(isIpLiteral("1.1.1"))
        assertFalse(isIpLiteral("256.1.1.1"))
        assertFalse(isIpLiteral(""))
        assertFalse(isIpLiteral(" "))
        assertFalse(isIpLiteral("not::ip"))
        assertFalse(isIpLiteral("1::2::3"))
        assertFalse(isIpLiteral("12345::"))
        assertFalse(isIpLiteral("1:2:3:4:5:6:7:8:9"))
        assertFalse(isIpLiteral("1:2:3:4:5:6:7"))
        assertFalse(isIpLiteral("fe80::1%en0"))
        assertFalse(isIpLiteral("::ffff:999.0.2.1"))
        assertFalse(isIpLiteral("01.1.1.1x"))
        // Only ASCII digits: Char.isDigit would take these Arabic-Indic ones.
        assertFalse(isIpLiteral("\u0661.\u0661.\u0661.\u0661"))
        assertFalse(isIpLiteral("\u0661::1"))
    }

    @Test
    fun test_encryptedUpstream_requiresNameAndAddresses() {
        assertFailsWith<IllegalArgumentException> { Upstream.Https("", listOf("1.1.1.1")) }
        assertFailsWith<IllegalArgumentException> { Upstream.Tls("dns.example", emptyList()) }
        assertFailsWith<IllegalArgumentException> { Upstream.Quic("dns.example", listOf("dns.example")) }
        assertFailsWith<IllegalArgumentException> { Upstream.Http3("dns.example", listOf("1.1.1.1"), path = "dns-query") }
        assertFailsWith<IllegalArgumentException> { Upstream.Tls("dns.example", listOf("1.1.1.1"), port = 0) }
    }

    @Test
    fun test_defaults_matchTheRfcPorts() {
        assertEquals(443, Upstream.Https("d", listOf("1.1.1.1")).port)
        assertEquals(443, Upstream.Http3("d", listOf("1.1.1.1")).port)
        assertEquals(853, Upstream.Tls("d", listOf("1.1.1.1")).port)
        assertEquals(853, Upstream.Quic("d", listOf("1.1.1.1")).port)
        assertEquals(53, Upstream.Plain(listOf("1.1.1.1")).port)
        assertEquals("/dns-query", Upstream.Https("d", listOf("1.1.1.1")).path)
    }

    @Test
    fun test_json_namesTheProtocol() {
        assertTrue(Upstream.Tls("d", listOf("1.1.1.1")).json().startsWith("""{"protocol":"tls""""))
        assertTrue(Upstream.Quic("d", listOf("1.1.1.1")).json().startsWith("""{"protocol":"quic""""))
        assertTrue(Upstream.Http3("d", listOf("1.1.1.1")).json().startsWith("""{"protocol":"h3""""))
        assertTrue(""""path":"/dns-query"""" in Upstream.Http3("d", listOf("1.1.1.1")).json())
        assertFalse(""""path"""" in Upstream.Tls("d", listOf("1.1.1.1")).json())
    }

    @Test
    fun test_presets_areWellFormedAndDistinct() {
        val names = Upstreams.all.map { it.serverName }
        assertEquals(names.size, names.toSet().size)
        Upstreams.all.forEach { provider ->
            assertTrue(provider.addresses.size >= 2, provider.name)
            assertTrue(provider.addresses.any { ':' in it }, "${provider.name} has no IPv6 address")
            assertEquals(provider.serverName, provider.https().serverName)
            assertEquals(provider.addresses, provider.tls().addresses)
        }
    }

    @Test
    fun test_recordType_namesTheCommonCodesAndNumbersTheRest() {
        assertEquals("A", RecordType.A.toString())
        assertEquals("HTTPS", RecordType(65).toString())
        assertEquals("TYPE99", RecordType(99).toString())
        assertEquals(RecordType.AAAA, RecordType(28))
        assertFailsWith<IllegalArgumentException> { RecordType(0) }
    }

    @Test
    fun test_unescapeField_undoesTheNativeEscaping() {
        assertEquals("a\tb\nc\\d\re", "a\\009b\\010c\\\\d\\013e".unescapeField())
        assertEquals("plain", "plain".unescapeField())
        assertEquals("\\065 stays", "\\065 stays".unescapeField())
    }

    @Test
    fun test_dnsRecord_valueSemantics() {
        val a = DnsRecord("example.com.", RecordType.A, 300, "93.184.216.34")
        val b = DnsRecord("example.com.", RecordType.A, 300, "93.184.216.34")

        assertEquals(a, b)
        assertEquals(a.hashCode(), b.hashCode())
        assertEquals("example.com. 300 A 93.184.216.34", a.toString())
        assertEquals(listOf("93.184.216.34"), DnsAnswer(listOf(a), DnsSecurity.Unvalidated).ipAddresses)
    }
}
