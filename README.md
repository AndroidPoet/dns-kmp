# dns-kmp

Encrypted DNS for Kotlin Multiplatform. A resolver that speaks DNS over HTTPS,
DNS over TLS and DNS over QUIC, validates DNSSEC if you ask, and runs inside your
app on Android, iOS, JVM, macOS, Linux and Windows. Built on
[hickory-dns](https://github.com/hickory-dns/hickory-dns), the Rust resolver, which
is compiled into the library.

```kotlin
val dns = DnsResolver(DnsConfig(upstreams = listOf(Upstreams.Quad9.https()), dnssec = true))
val addresses = dns.lookupIp("example.com")          // ["23.192.228.80", "2600:1406:…"]
val mail = dns.lookup("example.com", RecordType.MX)  // records + DnsSecurity.Secure
```

It talks only to the upstreams you configure. There is no system-resolver
fallback and no plaintext bootstrap: encrypted upstreams are given by IP address,
so the first query is already encrypted. Error messages never contain the name
you looked up, nothing is logged unless you ask, and no DNS data touches the disk.

## Why

Every HTTP client on these platforms resolves names through the operating
system, which on most networks means plaintext UDP to whatever the network
handed out: the ISP, the hotel, the coffee shop. That resolver sees every host
your app contacts, can answer wrongly, and often does (ISP-level blocking of
whole APIs is common). The platforms' own encrypted-DNS settings are
system-wide and user-controlled; an app cannot turn them on for itself.

dns-kmp gives the app its own resolver, with the transport, the operator and
the validation policy chosen by the app, the same on every platform.

## Install

```kotlin
// build.gradle.kts
kotlin {
    sourceSets {
        commonMain.dependencies {
            implementation("io.github.androidpoet:dns:0.1.0")
        }
        // Android and JVM: plug the resolver into OkHttp (and Ktor's OkHttp engine)
        androidMain.dependencies { implementation("io.github.androidpoet:dns-okhttp:0.1.0") }
        jvmMain.dependencies { implementation("io.github.androidpoet:dns-okhttp:0.1.0") }
    }
}
```

The `dns` artifact bundles the Rust core for every target: an AAR with four
Android ABIs, a JVM jar with macOS, Linux and Windows libraries, and klibs with
the static library embedded for the Kotlin/Native targets. Nothing else to install.

## Quickstart

```kotlin
import io.github.androidpoet.dns.*

// One resolver per configuration; keep it, it holds the connections and the cache.
val dns = DnsResolver(
    DnsConfig(
        upstreams = listOf(Upstreams.Cloudflare.https(), Upstreams.Quad9.https()),
        dnssec = true,
    ),
)

// Addresses, both families by default, IPv4 first.
val ips: List<String> = dns.lookupIp("example.com")
val v6: List<String> = dns.lookupIp("example.com", IpFamily.Ipv6)

// Any record type.
val answer: DnsAnswer = dns.lookup("example.com", RecordType.TXT)
answer.records.forEach { println("${it.name} ${it.ttl} ${it.type} ${it.data}") }
println(answer.security)   // Secure, Insecure (unsigned zone) or Unvalidated (dnssec off)

// Failures are typed.
try {
    dns.lookupIp("no-such-name.invalid")
} catch (e: DnsException) {
    when (e.kind) {
        DnsErrorKind.NoRecords -> TODO("does not exist")
        DnsErrorKind.Timeout -> TODO("no upstream answered")
        DnsErrorKind.Bogus -> TODO("DNSSEC validation failed")
        else -> TODO(e.message!!)
    }
}

dns.close()
```

`DnsResolver()` with no arguments uses Cloudflare over DoH without validation.
Every method suspends on a worker thread and honours cancellation: cancelling the
coroutine cancels the query.

## Upstreams and transports

An `Upstream` is a server plus a transport:

```kotlin
Upstream.Https("doh.example.org", listOf("203.0.113.5", "2001:db8::5"))   // RFC 8484, HTTP/2, port 443, /dns-query
Upstream.Tls("dot.example.org", listOf("203.0.113.5"))                     // RFC 7858, port 853
Upstream.Quic("doq.example.org", listOf("203.0.113.5"))                    // RFC 9250, port 853
Upstream.Http3("doh.example.org", listOf("203.0.113.5"))                   // DoH over HTTP/3, port 443
Upstream.Plain(listOf("192.0.2.53"))                                       // UDP/TCP 53, unencrypted, explicit opt-in, cannot be mixed with the others
```

Encrypted upstreams need the server's IP addresses. That is deliberate: a
resolver that first looks up `doh.example.org` through the system resolver has
already leaked, and a network that lies about that name can redirect it.
`serverName` is what the certificate is checked against, with the Mozilla root
store compiled in.

`Upstreams` has the public operators with their published addresses, each over
DoH or DoT:

| Provider | `serverName` | Notes |
|---|---|---|
| `Upstreams.Cloudflare` | `cloudflare-dns.com` | 1.1.1.1 |
| `Upstreams.Quad9` | `dns.quad9.net` | blocks known-malicious domains |
| `Upstreams.Google` | `dns.google` | 8.8.8.8 |
| `Upstreams.Mullvad` | `dns.mullvad.net` | no logging, no filtering |
| `Upstreams.AdGuard` | `dns.adguard-dns.com` | blocks ads and trackers |

Picking an upstream is picking who sees your queries; read the operator's
privacy policy. The live test suite resolves through each provider's DoH and DoT
endpoint, so a stale entry fails the build rather than your users.

Several upstreams are tried in turn when one does not answer within `timeout`;
`attempts` bounds the retries. A query that reaches no upstream fails with
`DnsErrorKind.Timeout`. It is never retried in plaintext.

## DNSSEC

`DnsConfig(dnssec = true)` validates every answer in your process against the
root trust anchor. `DnsAnswer.security` is then `Secure` for a complete chain
or `Insecure` for a zone (or parent) that is not signed; a bad signature fails
the lookup with `DnsErrorKind.Bogus`. Validation costs extra queries for the
DNSKEY and DS records, which are cached like any other answer.

The public resolvers above validate on their side as well, and answer SERVFAIL
for a bogus name before this library sees any records (hickory sends queries
with the CD bit clear); that surfaces as `DnsErrorKind.ServerFailure`. Local
validation still matters: it is what stops an upstream, or anyone between you
and it, from forging a signed name.

## OkHttp and Ktor (`dns-okhttp`, Android and JVM)

```kotlin
val client = OkHttpClient.Builder().dns(dns).build()            // extension from dns-okhttp
// or
val okHttpDns: okhttp3.Dns = dns.asOkHttpDns()
```

Only name resolution changes; connections, TLS and pooling stay OkHttp's. A
failed lookup is an `UnknownHostException` whose cause is the `DnsException`
and whose message names the failure kind, not the host.

Ktor has no resolver hook of its own, so use its OkHttp engine with the same
adapter:

```kotlin
HttpClient(OkHttp) {
    engine { config { dns(dns) } }
}
```

Other Ktor engines (CIO, Darwin, Curl, WinHttp) and `NSURLSession` on Apple
platforms resolve through the operating system and cannot be redirected by a
library. There, use `lookupIp` and connect to the address yourself, or treat
this resolver as the source of truth for your own sockets.

## Privacy

- **Nothing but the configured upstreams.** No system resolver, no `/etc/hosts`,
  no fallback to port 53 when the encrypted upstream is down. Failing closed is
  the point. `Upstream.Plain` exists for networks where nothing else works, and a
  config that mixes it with encrypted upstreams is rejected, so it can never be
  the quiet fallback.
- **No plaintext bootstrap.** Upstreams are addressed by IP; the server name is
  only used for certificate verification and the HTTP host.
- **Errors do not name the query.** A `DnsException` says what went wrong
  (`the name does not exist`, `no upstream answered in time`), not which name;
  hickory's own messages are checked for the name and scrubbed. Exceptions from
  OkHttp itself can still name hosts; filter those before shipping them anywhere.
- **No logs, no DNS data on disk.** Nothing is logged unless the `DNSKMP_LOG`
  environment variable is set (then hickory's tracing goes to stderr, for
  debugging). The answer cache is in memory and dies with the resolver;
  `clearCache()` empties it early. The one file the library writes is its own
  native library, which the JVM extracts to a private temp directory at load.
- **What the upstream still sees.** Your queries, and your IP address. That is
  the operator you chose, under its policy. For an upstream that should not know
  who is asking, route the connection through Tor ([tor-kmp](https://github.com/AndroidPoet/tor-kmp)
  resolves inside the Tor network and needs no resolver at all).
- **What this does not do.** It does not change how the rest of your app, or the
  operating system, resolves names. A WebView, `NSURLSession`, `java.net.URL`
  or a Ktor CIO client keep using the system resolver unless you connect them
  by address yourself.

## Errors, timeouts, cancellation

| `DnsErrorKind` | Meaning |
|---|---|
| `NoRecords` | NXDOMAIN, or the name has no record of that type (NODATA) |
| `Timeout` | no upstream answered within `timeout` × `attempts` |
| `ServerFailure` | an upstream answered SERVFAIL or another error code (includes a public resolver's own DNSSEC failure) |
| `Refused` | an upstream refused the query |
| `Bogus` | local DNSSEC validation failed |
| `InvalidName` | not a valid DNS name |
| `Closed` | the resolver was closed |
| `Other` | anything else; the message has hickory's explanation |

`DnsConfig.timeout` (default 5 s) bounds one attempt at one upstream and
`attempts` (default 2) how many times the query is tried across them, so the
worst case is roughly `timeout × attempts`. Cancelling the calling coroutine
cancels the query at once; `close()` cancels every running lookup, which then
fails with `Closed`.

## Platform notes

| Platform | Notes |
|---|---|
| Android | `minSdk 24`. The AAR adds `INTERNET`. Four ABIs; the app's split configuration decides which ship. |
| iOS | `iosArm64`, `iosSimulatorArm64`, `iosX64`. The static library is inside the klib; link nothing. |
| macOS | `macosArm64`, `macosX64`. Same. |
| JVM | macOS (arm64, x64), Linux (x64, arm64, glibc ≥ 2.17), Windows x64 libraries in the jar; the right one is extracted and loaded on first use. |
| Linux | `linuxX64`, `linuxArm64` Kotlin/Native. |
| Windows | `mingwX64` Kotlin/Native. |

### Targets and verification

Live tests last run (0.1.0, 2026-10-28; Linux and Windows on GitHub runners, the rest on the maintainer's machine):

| Platform | Suites | Result |
|---|---|---|
| Android (API 36 emulator, arm64) | `dns` 32, `dns-okhttp` 3 | pass |
| iOS simulator (iPhone 17, arm64) | `dns` 32 | pass |
| macOS (Kotlin/Native arm64) | `dns` 32 | pass |
| JVM (macOS arm64) | `dns` 32, `dns-okhttp` 3 | pass |
| Linux x64 (GitHub runner: Kotlin/Native + JVM) | `dns` 32 native, `dns` 32 + `dns-okhttp` 3 JVM | pass ([run](https://github.com/AndroidPoet/dns-kmp/actions/runs/40718875012)) |
| Windows x64 (GitHub runner: JVM + Kotlin/Native mingwX64) | `dns` 32 + `dns-okhttp` 3 JVM, `dns` 32 native | pass ([run](https://github.com/AndroidPoet/dns-kmp/actions/runs/40722649722)) |

Linux and Windows run on GitHub's runners through the `Verify platforms`
workflow (linked above). The Rust core cross-compiles
for every target in the `Build` workflow's `apiCheck`.

## Maturity and provenance

- 0.x: the API can still change between minor versions; the CHANGELOG lists every change.
- The Rust core is hickory-resolver 0.26.3 with rustls (ring) and quinn, compiled
  by Gradle from the pinned `Cargo.lock` for every target; no binary is checked
  in. `cargo test --locked` and the Kotlin suites run in CI.
- hickory-dns is the resolver behind several Rust projects and the subject of a
  third-party audit of its DNSSEC implementation; see its repository for the
  current state. This library adds a thin FFI and no cryptography of its own.
- GitHub Actions are pinned to commit SHAs. There is no publish workflow:
  releases are built and uploaded from the maintainer's machine after every
  platform's live suite is green.

## Build & test

```sh
# Rust unit tests (no network)
(cd native && cargo test --locked)

# JVM + OkHttp, live
./gradlew :dns:jvmTest :dns-okhttp:jvmTest

# Kotlin/Native on this Mac
./gradlew :dns:macosArm64Test

# iOS simulator (pick a device that exists: xcrun simctl list devices)
./gradlew :dns:iosSimulatorArm64Test -Pdns.simulator="iPhone 17"

# Android, on a running emulator or device
./gradlew connectedAndroidTest

# Gates run before every push
./gradlew spotlessCheck detekt apiCheck
```

Needs the Rust toolchain in `native/rust-toolchain.toml` (rustup installs it),
`cargo-ndk` for Android, and `cargo-zigbuild` + zig to cross-build Linux and
Windows from a Mac. `-Pdns.rust.prune=true` deletes each target's cargo
intermediates after its build (disk), `-Pdns.jvm.allPlatforms=true` bundles
every desktop OS in the JVM jar (release builds do).

## Contributing

Issues and pull requests are welcome. Run the gates above before pushing; the
`Build` workflow runs them on pull requests. Please read the
[code of conduct](CODE_OF_CONDUCT.md).

## License

[MIT](LICENSE). hickory-dns is MIT or Apache-2.0.
