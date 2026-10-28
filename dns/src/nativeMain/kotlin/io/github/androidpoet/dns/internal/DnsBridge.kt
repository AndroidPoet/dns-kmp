package io.github.androidpoet.dns.internal

import cnames.structs.DnsKmp
import io.github.androidpoet.dns.DnsException
import io.github.androidpoet.dns.cinterop.dnskmp_cancel
import io.github.androidpoet.dns.cinterop.dnskmp_clear_cache
import io.github.androidpoet.dns.cinterop.dnskmp_create
import io.github.androidpoet.dns.cinterop.dnskmp_destroy
import io.github.androidpoet.dns.cinterop.dnskmp_last_error
import io.github.androidpoet.dns.cinterop.dnskmp_lookup
import io.github.androidpoet.dns.cinterop.dnskmp_shutdown
import io.github.androidpoet.dns.cinterop.dnskmp_string_free
import kotlinx.cinterop.ByteVar
import kotlinx.cinterop.CPointer
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.convert
import kotlinx.cinterop.toCPointer
import kotlinx.cinterop.toKString
import kotlinx.cinterop.toLong

/** Direct calls into the statically linked Rust library. */
@OptIn(ExperimentalForeignApi::class)
internal actual object DnsBridge {
    actual fun create(configJson: String): Long = (dnskmp_create(configJson) ?: throwLastError()).toLong()

    actual fun lookup(
        resolver: Long,
        id: Long,
        name: String,
        recordType: Int,
    ): String = dnskmp_lookup(resolver.resolver, id.toULong(), name, recordType.convert())?.consume() ?: throwLastError()

    actual fun cancel(
        resolver: Long,
        id: Long,
    ) = dnskmp_cancel(resolver.resolver, id.toULong())

    actual fun shutdown(resolver: Long) = dnskmp_shutdown(resolver.resolver)

    actual fun clearCache(resolver: Long) = dnskmp_clear_cache(resolver.resolver)

    actual fun destroy(resolver: Long) = dnskmp_destroy(resolver.resolver)

    private val Long.resolver: CPointer<DnsKmp> get() = toCPointer()!!

    private fun throwLastError(): Nothing = throw DnsException(dnskmp_last_error()?.consume() ?: "unknown native error")

    /** Copies a string returned by Rust and frees the original, whatever the copy does. */
    private fun CPointer<ByteVar>.consume(): String =
        try {
            toKString()
        } finally {
            dnskmp_string_free(this)
        }
}
