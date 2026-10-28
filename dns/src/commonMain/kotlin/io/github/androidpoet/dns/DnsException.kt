package io.github.androidpoet.dns

import kotlin.jvm.JvmOverloads

/**
 * A lookup or resolver operation failed. [kind] says how, so callers can tell a
 * name that does not exist from an upstream that did not answer.
 *
 * The message never contains the name that was looked up: an exception that
 * reaches a log or a crash reporter must not say what the user resolved.
 *
 * The single-argument constructor must exist on the JVM: the native library
 * throws this exception from JNI with `(String)`.
 */
public class DnsException
    @JvmOverloads
    constructor(
        message: String,
        public val kind: DnsErrorKind = DnsErrorKind.Other,
        cause: Throwable? = null,
    ) : Exception(message, cause)

/** Why a [DnsException] was thrown. */
public enum class DnsErrorKind {
    /** The name does not exist (NXDOMAIN) or has no record of the asked type. */
    NoRecords,

    /** No upstream answered within the configured timeout and attempts. */
    Timeout,

    /** An upstream answered with SERVFAIL or another error code. */
    ServerFailure,

    /** An upstream refused the query. */
    Refused,

    /** DNSSEC validation failed: the answer was signed badly or tampered with. */
    Bogus,

    /** The name is not a valid DNS name. */
    InvalidName,

    /** The resolver was closed. */
    Closed,

    /** Anything else; the message has the detail. */
    Other,
}
