package io.github.androidpoet.dns.internal

/** JNI bindings; implemented in Rust by native/src/java.rs. */
internal actual object DnsBridge {
    init {
        loadDnsLibrary()
    }

    @JvmStatic actual external fun create(configJson: String): Long

    @JvmStatic actual external fun lookup(
        resolver: Long,
        id: Long,
        name: String,
        recordType: Int,
    ): String

    @JvmStatic actual external fun cancel(
        resolver: Long,
        id: Long,
    )

    @JvmStatic actual external fun shutdown(resolver: Long)

    @JvmStatic actual external fun clearCache(resolver: Long)

    @JvmStatic actual external fun destroy(resolver: Long)
}

/** Loads libdnskmp: from the jar on desktop, from the APK's jniLibs on Android. */
internal expect fun loadDnsLibrary()
