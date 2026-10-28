package io.github.androidpoet.dns.okhttp

import io.github.androidpoet.dns.DnsConfig
import io.github.androidpoet.dns.DnsErrorKind
import io.github.androidpoet.dns.DnsException
import io.github.androidpoet.dns.DnsResolver
import io.github.androidpoet.dns.Upstreams
import okhttp3.OkHttpClient
import okhttp3.Request
import java.net.UnknownHostException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class OkHttpDnsTest {
    @Test
    fun test_dns_resolvesThroughTheResolver() {
        DnsResolver(DnsConfig(upstreams = listOf(Upstreams.Cloudflare.https()))).use { resolver ->
            val client = OkHttpClient.Builder().dns(resolver).build()

            val addresses = client.dns.lookup("example.com")
            val response = client.newCall(Request.Builder().url("https://example.com/").build()).execute()

            assertTrue(addresses.isNotEmpty())
            assertTrue(addresses.all { it.hostName == "example.com" })
            response.use { assertEquals(200, it.code) }
            client.dispatcher.executorService.shutdown()
            client.connectionPool.evictAll()
        }
    }

    @Test
    fun test_lookup_missingName_throwsUnknownHostWithTheKindNotTheName() {
        DnsResolver().use { resolver ->
            val dns = resolver.asOkHttpDns()

            val failure = assertFailsWith<UnknownHostException> { dns.lookup("this-name-does-not-exist-dns-kmp.invalid") }

            assertFalse("dns-kmp" in failure.message.orEmpty(), failure.message)
            val cause = failure.cause
            assertTrue(cause is DnsException && cause.kind == DnsErrorKind.NoRecords, cause.toString())
        }
    }

    @Test
    fun test_lookup_closedResolver_throwsUnknownHost() {
        val resolver = DnsResolver()
        resolver.close()

        val failure = assertFailsWith<UnknownHostException> { resolver.asOkHttpDns().lookup("example.com") }

        assertTrue((failure.cause as DnsException).kind == DnsErrorKind.Closed)
    }
}
