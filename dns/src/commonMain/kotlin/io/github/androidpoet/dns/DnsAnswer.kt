package io.github.androidpoet.dns

/**
 * One resource record from an answer.
 *
 * @property name the owner name, fully qualified and lowercase (`example.com.`).
 * @property type the record type.
 * @property ttl seconds the record may be cached for, as the upstream sent it (an unsigned 32-bit value).
 * @property data the record in hickory's presentation format: `93.184.216.34` for A,
 * `2606:4700::6810:84e5` for AAAA, `10 mail.example.com.` for MX, `0 5 5060 sip.example.com.`
 * for SRV; for TXT the text itself (a record's several strings concatenated, no quotes);
 * other types as in a zone file.
 */
public class DnsRecord(
    public val name: String,
    public val type: RecordType,
    public val ttl: Long,
    public val data: String,
) {
    override fun equals(other: Any?): Boolean =
        other is DnsRecord && other.name == name && other.type == type && other.ttl == ttl && other.data == data

    override fun hashCode(): Int = listOf(name, type, ttl, data).hashCode()

    override fun toString(): String = "$name $ttl $type $data"
}

/** What DNSSEC says about an answer. */
public enum class DnsSecurity {
    /** Every record is signed and the chain of trust reaches the root. Only with [DnsConfig.dnssec] on. */
    Secure,

    /** The zone (or a parent) is unsigned, so the records could not be verified. Only with [DnsConfig.dnssec] on. */
    Insecure,

    /** The resolver was not asked to validate ([DnsConfig.dnssec] is off). */
    Unvalidated,
}

/**
 * The records returned for a lookup, with CNAME records that led to them when
 * the name is an alias.
 */
public class DnsAnswer(
    public val records: List<DnsRecord>,
    public val security: DnsSecurity,
) {
    /** The A and AAAA records' addresses, in upstream order. */
    public val ipAddresses: List<String>
        get() = records.filter { it.type == RecordType.A || it.type == RecordType.AAAA }.map(DnsRecord::data)

    override fun equals(other: Any?): Boolean = other is DnsAnswer && other.records == records && other.security == security

    override fun hashCode(): Int = records.hashCode() * 31 + security.hashCode()

    override fun toString(): String = "DnsAnswer(${records.size} records, $security)"
}

/** Which address families [DnsResolver.lookupIp] asks for. */
public enum class IpFamily {
    /** A records only. */
    Ipv4,

    /** AAAA records only. */
    Ipv6,

    /** Both, IPv4 addresses first. */
    Both,
}
