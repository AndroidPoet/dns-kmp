package io.github.androidpoet.dns

/**
 * A DNS server the resolver sends queries to, and how it reaches it.
 *
 * Encrypted upstreams take the server's IP [addresses] as well as its name, so
 * the resolver never has to look the server up in the clear first. The IPs of
 * the well-known public resolvers are in [Upstreams]; for your own server use
 * the addresses your operator publishes.
 *
 * Two upstreams are equal when every setting is equal.
 *
 * @throws IllegalArgumentException when a required field is blank, no address
 * is given, or an address is not an IP literal.
 */
public sealed class Upstream {
    /** The IP addresses the resolver connects to. */
    public abstract val addresses: List<String>

    /** The port the resolver connects to. */
    public abstract val port: Int

    /** DNS over HTTPS (RFC 8484) over HTTP/2. */
    public class Https(
        /** The name on the server's certificate, also used as the HTTP host. */
        public val serverName: String,
        override val addresses: List<String>,
        /** The query path on the server. */
        public val path: String = DEFAULT_PATH,
        override val port: Int = HTTPS_PORT,
    ) : Upstream() {
        init {
            validate(serverName, addresses, port)
            require(path.startsWith('/')) { "path must start with /" }
        }

        override fun toString(): String = "https://$serverName$path (${addresses.joinToString()})"
    }

    /** DNS over TLS (RFC 7858). */
    public class Tls(
        /** The name on the server's certificate. */
        public val serverName: String,
        override val addresses: List<String>,
        override val port: Int = TLS_PORT,
    ) : Upstream() {
        init {
            validate(serverName, addresses, port)
        }

        override fun toString(): String = "tls://$serverName:$port (${addresses.joinToString()})"
    }

    /** DNS over QUIC (RFC 9250). */
    public class Quic(
        /** The name on the server's certificate. */
        public val serverName: String,
        override val addresses: List<String>,
        override val port: Int = TLS_PORT,
    ) : Upstream() {
        init {
            validate(serverName, addresses, port)
        }

        override fun toString(): String = "quic://$serverName:$port (${addresses.joinToString()})"
    }

    /** DNS over HTTPS over HTTP/3. */
    public class Http3(
        /** The name on the server's certificate, also used as the HTTP host. */
        public val serverName: String,
        override val addresses: List<String>,
        /** The query path on the server. */
        public val path: String = DEFAULT_PATH,
        override val port: Int = HTTPS_PORT,
    ) : Upstream() {
        init {
            validate(serverName, addresses, port)
            require(path.startsWith('/')) { "path must start with /" }
        }

        override fun toString(): String = "h3://$serverName$path (${addresses.joinToString()})"
    }

    /**
     * Classic unencrypted DNS over UDP and TCP (RFC 1035). Every query and
     * answer is visible to the network; use it only when nothing else is
     * reachable, and never by accident: there is no default that picks it, and
     * [DnsConfig] refuses to mix it with encrypted upstreams.
     */
    public class Plain(
        override val addresses: List<String>,
        override val port: Int = PLAIN_PORT,
    ) : Upstream() {
        init {
            validate("plain", addresses, port)
        }

        override fun toString(): String = "dns://${addresses.joinToString()}:$port"
    }

    final override fun equals(other: Any?): Boolean = other is Upstream && other.json() == json()

    final override fun hashCode(): Int = json().hashCode()

    public companion object {
        /** The RFC 8484 default query path. */
        public const val DEFAULT_PATH: String = "/dns-query"
        private const val HTTPS_PORT = 443
        private const val TLS_PORT = 853
        private const val PLAIN_PORT = 53

        private fun validate(
            serverName: String,
            addresses: List<String>,
            port: Int,
        ) {
            require(serverName.isNotBlank()) { "serverName must not be blank" }
            require(addresses.isNotEmpty()) { "an upstream needs at least one IP address" }
            addresses.forEach { require(isIpLiteral(it)) { "upstream addresses must be IP literals, not names" } }
            require(port in 1..0xFFFF) { "port must be 1..65535" }
        }
    }
}

/** The upstream as the native side reads it (see `Upstream` in native/src/lib.rs). */
internal fun Upstream.json(): String {
    val protocol: String
    val serverName: String
    val path: String?
    when (this) {
        is Upstream.Https -> {
            protocol = "https"
            serverName = this.serverName
            path = this.path
        }
        is Upstream.Tls -> {
            protocol = "tls"
            serverName = this.serverName
            path = null
        }
        is Upstream.Quic -> {
            protocol = "quic"
            serverName = this.serverName
            path = null
        }
        is Upstream.Http3 -> {
            protocol = "h3"
            serverName = this.serverName
            path = this.path
        }
        is Upstream.Plain -> {
            protocol = "plain"
            serverName = ""
            path = null
        }
    }
    val fields =
        buildList {
            add(""""protocol":${protocol.jsonQuoted()}""")
            add(""""serverName":${serverName.jsonQuoted()}""")
            add(""""addresses":[${addresses.joinToString(",") { it.jsonQuoted() }}]""")
            if (path != null) add(""""path":${path.jsonQuoted()}""")
            add(""""port":$port""")
        }
    return fields.joinToString(",", prefix = "{", postfix = "}")
}

/** True when [text] is an IPv4 dotted quad or an IPv6 address (RFC 4291 text form, no zone). */
internal fun isIpLiteral(text: String): Boolean = isIpv4Literal(text) || isIpv6Literal(text)

private fun isIpv4Literal(text: String): Boolean {
    val parts = text.split('.')
    return parts.size == 4 && parts.all { part -> part.length in 1..3 && part.all { it in '0'..'9' } && part.toInt() in 0..255 }
}

private fun isIpv6Literal(text: String): Boolean {
    if (text.isEmpty() || text.count { it == ':' } < 2) return false
    val halves = text.split("::")
    if (halves.size > 2) return false
    val compressed = halves.size == 2
    val groups = halves.flatMap { half -> if (half.isEmpty()) emptyList() else half.split(':') }.toMutableList()
    var groupCount = 0
    val last = groups.lastOrNull()
    if (last != null && '.' in last) {
        // An embedded IPv4 tail counts as two groups.
        if (!isIpv4Literal(last)) return false
        groups.removeAt(groups.lastIndex)
        groupCount += 2
    }
    if (groups.any { group -> group.length !in 1..4 || !group.all { it in '0'..'9' || it.lowercaseChar() in 'a'..'f' } }) return false
    groupCount += groups.size
    return if (compressed) groupCount < 8 else groupCount == 8
}

/** A JSON string literal for [this], escaping what RFC 8259 requires. */
internal fun String.jsonQuoted(): String =
    buildString(length + 2) {
        append('"')
        for (char in this@jsonQuoted) {
            when {
                char == '"' -> append("\\\"")
                char == '\\' -> append("\\\\")
                char < ' ' -> append("\\u").append(char.code.toString(16).padStart(4, '0'))
                else -> append(char)
            }
        }
        append('"')
    }
