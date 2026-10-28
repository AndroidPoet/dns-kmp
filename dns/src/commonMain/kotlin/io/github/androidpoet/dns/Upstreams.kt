package io.github.androidpoet.dns

/**
 * Public resolvers that speak DNS over HTTPS and DNS over TLS, with their
 * published IP addresses, so an app can pick one without looking anything up:
 *
 * ```
 * DnsConfig(upstreams = listOf(Upstreams.Quad9.https()))
 * DnsConfig(upstreams = listOf(Upstreams.Cloudflare.tls(), Upstreams.Google.tls()))
 * ```
 *
 * Choosing an upstream is choosing who sees your queries; each operator's
 * privacy policy is theirs, not this library's. The addresses are the ones
 * each operator publishes; the live test suite checks every entry answers.
 */
public object Upstreams {
    /** One operator's DoH and DoT endpoints. */
    public class Provider(
        /** The operator, for display. */
        public val name: String,
        /** The name on the certificate, shared by the DoH and DoT endpoints. */
        public val serverName: String,
        /** Published IPv4 and IPv6 addresses. */
        public val addresses: List<String>,
        /** The DoH query path. */
        public val path: String = Upstream.DEFAULT_PATH,
    ) {
        /** This operator over DNS over HTTPS. */
        public fun https(): Upstream.Https = Upstream.Https(serverName, addresses, path)

        /** This operator over DNS over TLS. */
        public fun tls(): Upstream.Tls = Upstream.Tls(serverName, addresses)

        override fun toString(): String = "$name ($serverName)"
    }

    /** Cloudflare, 1.1.1.1. */
    public val Cloudflare: Provider =
        Provider(
            name = "Cloudflare",
            serverName = "cloudflare-dns.com",
            addresses = listOf("1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"),
        )

    /** Quad9, 9.9.9.9; blocks known-malicious domains. */
    public val Quad9: Provider =
        Provider(
            name = "Quad9",
            serverName = "dns.quad9.net",
            addresses = listOf("9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"),
        )

    /** Google Public DNS, 8.8.8.8. */
    public val Google: Provider =
        Provider(
            name = "Google",
            serverName = "dns.google",
            addresses = listOf("8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"),
        )

    /** Mullvad's public resolver, no logging, no filtering. */
    public val Mullvad: Provider =
        Provider(
            name = "Mullvad",
            serverName = "dns.mullvad.net",
            addresses = listOf("194.242.2.2", "2a07:e340::2"),
        )

    /** AdGuard DNS, default profile; blocks ads and trackers. */
    public val AdGuard: Provider =
        Provider(
            name = "AdGuard",
            serverName = "dns.adguard-dns.com",
            addresses = listOf("94.140.14.14", "94.140.15.15", "2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff"),
        )

    /** Every provider above, for tests and pickers. */
    public val all: List<Provider> = listOf(Cloudflare, Quad9, Google, Mullvad, AdGuard)
}
