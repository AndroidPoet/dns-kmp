package io.github.androidpoet.dns

import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * How a [DnsResolver] behaves: which servers it asks, over which transport,
 * and whether it validates DNSSEC.
 *
 * ```
 * DnsConfig()                                                    // Cloudflare over DoH
 * DnsConfig(upstreams = listOf(Upstreams.Quad9.tls()), dnssec = true)
 * DnsConfig(upstreams = listOf(Upstream.Https("doh.example.org", listOf("203.0.113.5"))))
 * ```
 *
 * The resolver talks only to [upstreams]. It never falls back to the system
 * resolver or to plaintext DNS, so a lookup that cannot reach an upstream fails
 * rather than leaking.
 *
 * @property upstreams the servers to query; several are tried in turn when one
 * does not answer. At least one. Either all encrypted or all [Upstream.Plain]:
 * a plaintext upstream next to encrypted ones would be their fallback.
 * @property dnssec validate answers against the DNSSEC root trust anchor, in
 * this process, so a lying upstream cannot forge a signed name. A tampered or
 * badly signed answer then fails with [DnsErrorKind.Bogus] instead of being
 * returned, and [DnsAnswer.security] says whether the chain was complete.
 * Public resolvers validate on their side too and answer SERVFAIL for a bogus
 * name before this library sees the records; that surfaces as
 * [DnsErrorKind.ServerFailure].
 * @property timeout how long one attempt at one upstream may take.
 * @property attempts how many times a query is retried across the upstreams.
 * @property cacheSize how many answers are kept in memory, honouring their TTL;
 * `0` disables the cache. Nothing is ever written to disk.
 * @property ipFamily which address records [DnsResolver.lookupIp] asks for by default.
 */
public class DnsConfig(
    public val upstreams: List<Upstream> = listOf(Upstreams.Cloudflare.https()),
    public val dnssec: Boolean = false,
    public val timeout: Duration = 5.seconds,
    public val attempts: Int = 2,
    public val cacheSize: Int = 1024,
    public val ipFamily: IpFamily = IpFamily.Both,
) {
    init {
        require(upstreams.isNotEmpty()) { "at least one upstream is required" }
        val plain = upstreams.count { it is Upstream.Plain }
        require(plain == 0 || plain == upstreams.size) {
            "Upstream.Plain cannot be mixed with encrypted upstreams: it would become their plaintext fallback"
        }
        require(timeout.inWholeMilliseconds >= 1) { "timeout must be at least 1 millisecond" }
        require(attempts >= 1) { "attempts must be at least 1" }
        require(cacheSize >= 0) { "cacheSize must not be negative" }
    }

    /** The configuration as the native side reads it. */
    internal fun settingsJson(): String {
        val family =
            when (ipFamily) {
                IpFamily.Ipv4 -> "ipv4"
                IpFamily.Ipv6 -> "ipv6"
                IpFamily.Both -> "both"
            }
        return buildString {
            append("{\"upstreams\":[")
            append(upstreams.joinToString(",") { it.json() })
            append("],\"dnssec\":").append(dnssec)
            append(",\"timeoutMs\":").append(timeout.inWholeMilliseconds)
            append(",\"attempts\":").append(attempts)
            append(",\"cacheSize\":").append(cacheSize)
            append(",\"ipFamily\":\"").append(family).append("\"}")
        }
    }

    override fun equals(other: Any?): Boolean = other is DnsConfig && other.settingsJson() == settingsJson()

    override fun hashCode(): Int = settingsJson().hashCode()

    override fun toString(): String =
        "DnsConfig(upstreams=$upstreams, dnssec=$dnssec, timeout=$timeout, attempts=$attempts, cacheSize=$cacheSize, ipFamily=$ipFamily)"
}
