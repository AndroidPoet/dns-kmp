package io.github.androidpoet.dns.okhttp

import io.github.androidpoet.dns.DnsErrorKind
import io.github.androidpoet.dns.DnsException
import io.github.androidpoet.dns.DnsResolver
import kotlinx.coroutines.runBlocking
import okhttp3.Dns
import okhttp3.OkHttpClient
import java.net.InetAddress
import java.net.UnknownHostException

/**
 * Makes OkHttp resolve every host through [this] instead of the system resolver:
 *
 * ```
 * val client = OkHttpClient.Builder().dns(resolver).build()
 * ```
 *
 * With the Ktor OkHttp engine, pass the same thing through the engine config:
 * `engine { config { dns(resolver) } }`.
 *
 * Only name resolution changes; the connection itself is OkHttp's. Close the
 * resolver after the client.
 *
 * OkHttp's [Dns] interface is synchronous, so the adapter blocks the thread
 * that calls `lookup` for up to the resolver's timeout × attempts. OkHttp calls
 * it from its own dispatcher threads (or the thread that calls `execute()`),
 * never pass it work from the main thread directly.
 */
public fun OkHttpClient.Builder.dns(resolver: DnsResolver): OkHttpClient.Builder = dns(resolver.asOkHttpDns())

/**
 * [this] as an OkHttp [Dns]. A failed lookup throws [UnknownHostException], as
 * OkHttp requires, with the [DnsException] as its cause; the message names the
 * failure kind, not the host.
 */
public fun DnsResolver.asOkHttpDns(): Dns = ResolverDns(this)

private class ResolverDns(
    private val resolver: DnsResolver,
) : Dns {
    override fun lookup(hostname: String): List<InetAddress> {
        val addresses =
            try {
                runBlocking { resolver.lookupIp(hostname) }
            } catch (error: DnsException) {
                throw UnknownHostException("lookup failed: ${error.kind}").initCause(error)
            }
        if (addresses.isEmpty()) {
            throw UnknownHostException("lookup failed: ${DnsErrorKind.NoRecords}")
                .initCause(DnsException("the name has no addresses", DnsErrorKind.NoRecords))
        }
        // getByName on an IP literal only parses it; the hostname is kept so
        // OkHttp's own logging and the connection show the name, not the IP.
        return addresses.map { InetAddress.getByAddress(hostname, InetAddress.getByName(it).address) }
    }

    override fun toString(): String = "dns-kmp($resolver)"
}
