package io.github.androidpoet.dns.internal

/** The AAR ships libdnskmp.so per ABI in jniLibs; the platform loader finds it. */
internal actual fun loadDnsLibrary() {
    System.loadLibrary("dnskmp")
}
