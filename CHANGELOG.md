# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.1.0 - Unreleased

First release.

### Added

- `dns`: `DnsResolver` on hickory-dns 0.26, running inside the process on Android,
  JVM, iOS, macOS, Linux and Windows. Transports: DNS over HTTPS, DNS over TLS,
  DNS over QUIC, DNS over HTTPS/3, and plaintext UDP/TCP as an explicit opt-in.
  Optional DNSSEC validation with the root trust anchor. In-memory TTL cache.
  `lookupIp` for addresses and `lookup` for any record type.
- `Upstreams`: Cloudflare, Quad9, Google, Mullvad and AdGuard with their published
  addresses, over DoH or DoT.
- `dns-okhttp`: `OkHttpClient.Builder.dns(resolver)` and `DnsResolver.asOkHttpDns()`
  so OkHttp, and Ktor's OkHttp engine, resolve through the library.
- Privacy defaults: the resolver talks only to the configured upstreams (no system
  resolver, no plaintext bootstrap: encrypted upstreams are configured by IP), error
  messages never contain the name that was looked up, nothing is logged unless
  `DNSKMP_LOG` is set, and nothing is written to disk.
