package io.github.androidpoet.dns

import kotlin.jvm.JvmInline

/**
 * A DNS record type by its IANA code. The common ones are named here; any other
 * code can be asked for with the constructor.
 */
@JvmInline
public value class RecordType(
    public val code: Int,
) {
    init {
        require(code in 1..0xFFFF) { "a record type code is 1..65535" }
    }

    /** The mnemonic (`A`, `MX`, ...) or `TYPE<code>` for one without a name here. */
    override fun toString(): String = NAMES[code] ?: "TYPE$code"

    public companion object {
        public val A: RecordType = RecordType(1)
        public val NS: RecordType = RecordType(2)
        public val CNAME: RecordType = RecordType(5)
        public val SOA: RecordType = RecordType(6)
        public val PTR: RecordType = RecordType(12)
        public val MX: RecordType = RecordType(15)
        public val TXT: RecordType = RecordType(16)
        public val AAAA: RecordType = RecordType(28)
        public val SRV: RecordType = RecordType(33)
        public val SVCB: RecordType = RecordType(64)
        public val HTTPS: RecordType = RecordType(65)
        public val CAA: RecordType = RecordType(257)

        private val NAMES =
            mapOf(
                1 to "A",
                2 to "NS",
                5 to "CNAME",
                6 to "SOA",
                12 to "PTR",
                15 to "MX",
                16 to "TXT",
                28 to "AAAA",
                33 to "SRV",
                64 to "SVCB",
                65 to "HTTPS",
                257 to "CAA",
            )
    }
}
