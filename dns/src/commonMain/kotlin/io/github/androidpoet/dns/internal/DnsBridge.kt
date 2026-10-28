package io.github.androidpoet.dns.internal

/**
 * One-to-one view of the Rust C ABI (native/include/dnskmp.h). Handles are raw
 * pointers stored as [Long]. Every call blocks. A misuse of the ABI throws
 * [io.github.androidpoet.dns.DnsException]; a DNS failure comes back inside the
 * text [lookup] returns.
 *
 * Callers must keep a handle alive for the duration of a call; [NativeHandle]
 * does that.
 */
internal expect object DnsBridge {
    /** [configJson] is the JSON from DnsConfig.settingsJson. */
    fun create(configJson: String): Long

    /**
     * Resolves [name]; [recordType] is a DNS type code, or 0 for addresses. [id]
     * names the call for [cancel]. Returns the tab-separated text described in
     * lib.rs (`OK` + records, or `ERR` + kind + message).
     */
    fun lookup(
        resolver: Long,
        id: Long,
        name: String,
        recordType: Int,
    ): String

    fun cancel(
        resolver: Long,
        id: Long,
    )

    /** Cancels every running lookup and refuses new ones. */
    fun shutdown(resolver: Long)

    fun clearCache(resolver: Long)

    fun destroy(resolver: Long)
}
