package io.github.androidpoet.dns

import io.github.androidpoet.dns.internal.DnsBridge
import io.github.androidpoet.dns.internal.NativeHandle
import io.github.androidpoet.dns.internal.cancellableBlocking
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.isActive
import kotlin.concurrent.atomics.AtomicLong
import kotlin.concurrent.atomics.incrementAndFetch

/**
 * An encrypted DNS resolver running hickory-dns inside your process. Queries go
 * to the configured upstreams over DoH, DoT or DoQ and nowhere else.
 *
 * ```
 * val dns = DnsResolver(DnsConfig(upstreams = listOf(Upstreams.Quad9.https()), dnssec = true))
 * val addresses = dns.lookupIp("example.com")
 * val mail = dns.lookup("example.com", RecordType.MX)
 * ```
 *
 * Create one per configuration and keep it: it holds the connections to the
 * upstreams and the answer cache. [close] it when done. Every method is safe
 * to call from any thread.
 *
 * @throws DnsException if the configuration cannot be turned into a resolver.
 */
public class DnsResolver(
    public val config: DnsConfig = DnsConfig(),
) : AutoCloseable {
    private val handle =
        NativeHandle(
            pointer = DnsBridge.create(config.settingsJson()),
            name = "DnsResolver",
            shutdown = DnsBridge::shutdown,
            free = DnsBridge::destroy,
        )
    private val lookupIds = AtomicLong(0)

    /**
     * Resolves [host] to IP addresses. An IP literal is returned as is, without
     * a query (or as an empty list when it is not of the asked [family]).
     *
     * @param family which records to ask for; defaults to [DnsConfig.ipFamily].
     * @throws DnsException with [DnsErrorKind.NoRecords] when the name does not
     * exist or has no address of the asked family, or another kind when the
     * upstreams could not answer.
     */
    public suspend fun lookupIp(
        host: String,
        family: IpFamily = config.ipFamily,
    ): List<String> {
        if (isIpLiteral(host)) {
            val isV6 = ':' in host
            val wanted =
                when (family) {
                    IpFamily.Ipv4 -> !isV6
                    IpFamily.Ipv6 -> isV6
                    IpFamily.Both -> true
                }
            return if (wanted) listOf(host) else emptyList()
        }
        val code =
            when (family) {
                IpFamily.Ipv4 -> RecordType.A.code
                IpFamily.Ipv6 -> RecordType.AAAA.code
                IpFamily.Both -> IP_LOOKUP
            }
        return query(host, code).ipAddresses
    }

    /**
     * Resolves [name] to its records of [type].
     *
     * @throws DnsException with [DnsErrorKind.NoRecords] when there are none,
     * [DnsErrorKind.Bogus] when DNSSEC validation fails, or another kind when
     * the upstreams could not answer.
     */
    public suspend fun lookup(
        name: String,
        type: RecordType,
    ): DnsAnswer = query(name, type.code)

    /** Forgets every cached answer. */
    public fun clearCache() {
        handle.use(DnsBridge::clearCache)
    }

    /** True after [close]. */
    public val isClosed: Boolean get() = handle.isClosed

    /**
     * Cancels running lookups and releases the native resolver. Lookups started
     * afterwards throw [DnsException] with [DnsErrorKind.Closed].
     */
    override fun close() {
        handle.close()
    }

    private suspend fun query(
        name: String,
        typeCode: Int,
    ): DnsAnswer {
        val id = lookupIds.incrementAndFetch()
        val text =
            cancellableBlocking(
                onCancel = { runCatching { handle.use { DnsBridge.cancel(it, id) } } },
            ) {
                handle.use { DnsBridge.lookup(it, id, name, typeCode) }
            }
        return parse(text)
    }

    private suspend fun parse(text: String): DnsAnswer {
        val lines = text.split('\n')
        val header = lines.first().split('\t')
        return when (header.firstOrNull()) {
            "OK" -> answer(header.getOrNull(1), lines.drop(1))
            "ERR" -> throw failure(header.getOrNull(1).orEmpty(), header.getOrNull(2).orEmpty().unescapeField())
            else -> throw DnsException("unexpected reply from the native resolver")
        }
    }

    private fun answer(
        security: String?,
        lines: List<String>,
    ): DnsAnswer {
        val records =
            lines.filter(String::isNotEmpty).map { line ->
                val fields = line.split('\t', limit = 4)
                require(fields.size == 4) { "malformed record line from the native resolver" }
                DnsRecord(
                    name = fields[0].unescapeField(),
                    type = RecordType(fields[1].toInt()),
                    ttl = fields[2].toLong(),
                    data = fields[3].unescapeField(),
                )
            }
        val dnsSecurity =
            when (security) {
                "secure" -> DnsSecurity.Secure
                "insecure" -> DnsSecurity.Insecure
                else -> DnsSecurity.Unvalidated
            }
        return DnsAnswer(records, dnsSecurity)
    }

    /**
     * The exception for an `ERR` reply. A cancel of our own surfaces as the
     * coroutine's cancellation, or as [DnsErrorKind.Closed] when [close] pulled
     * the resolver away.
     */
    private suspend fun failure(
        kind: String,
        message: String,
    ): Exception {
        if (kind == "Cancelled") {
            return if (currentCoroutineContext().isActive) {
                DnsException(message, DnsErrorKind.Closed)
            } else {
                CancellationException("lookup cancelled")
            }
        }
        return DnsException(message, DnsErrorKind.entries.firstOrNull { it.name == kind } ?: DnsErrorKind.Other)
    }

    override fun toString(): String = "DnsResolver($config)"

    private companion object {
        /** Record type code the native side reads as "addresses per the configured family". */
        const val IP_LOOKUP = 0
    }
}

/** Undoes the escaping lib.rs applies to a field (`\009` tab, `\010` newline, `\013` CR, `\\` backslash). */
internal fun String.unescapeField(): String {
    if ('\\' !in this) return this
    val out = StringBuilder(length)
    var i = 0
    while (i < length) {
        val escape = escapeAt(i)
        if (escape == null) {
            out.append(this[i])
            i++
        } else {
            out.append(escape.first)
            i += escape.second
        }
    }
    return out.toString()
}

/** The character the escape sequence at [index] stands for and its length, or null when there is none. */
private fun String.escapeAt(index: Int): Pair<Char, Int>? {
    if (this[index] != '\\' || index + 1 >= length) return null
    if (this[index + 1] == '\\') return '\\' to 2
    if (index + 3 >= length) return null
    val digits = substring(index + 1, index + 4)
    if (!digits.all(Char::isDigit)) return null
    return when (val code = digits.toInt()) {
        9, 10, 13 -> code.toChar() to 4
        else -> null
    }
}
