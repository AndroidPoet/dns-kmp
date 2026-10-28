//! C ABI over an in-process hickory-dns resolver. Mirrored by `include/dnskmp.h`.
//!
//! Conventions:
//! - Every call is blocking; the Kotlin side runs them off the main thread.
//! - A lookup returns a tab-separated text document (see [`lookup_text`]) that
//!   carries either the records or a typed DNS failure. Only a misuse of the
//!   ABI (null pointer, bad UTF-8) returns NULL, explained by
//!   `dnskmp_last_error`, which must be read on the same thread right after.
//! - Handles are freed exactly once. The Kotlin wrapper guarantees no call is in
//!   flight when it frees one.
//! - Error text never contains the name that was looked up. hickory's own error
//!   messages are checked for it and it is replaced, so a message that ends up
//!   in a log or a crash report does not say what the user resolved.
//! - The resolver only ever talks to the upstreams it was given. There is no
//!   system-resolver fallback and no plaintext bootstrap: encrypted upstreams
//!   are configured by IP address.

#[cfg(feature = "jni")]
mod java;

use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::ffi::{c_char, CStr, CString};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Once};
use std::time::Duration;

use hickory_resolver::config::{
    ConnectionConfig, LookupIpStrategy, NameServerConfig, ResolveHosts, ResolverConfig,
    ResolverOpts,
};
use hickory_resolver::lookup::Lookup;
use hickory_resolver::net::{DnsError, NetError};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::dnssec::Proof;
use hickory_resolver::proto::op::ResponseCode;
use hickory_resolver::proto::rr::{Name, RecordType};
use hickory_resolver::{Resolver, TokioResolver};
use serde::Deserialize;
use tokio::runtime::Runtime;
use tokio::sync::watch;

/// Record type code that asks for addresses (A and AAAA per the configured
/// family) instead of one record type.
pub const IP_LOOKUP: u16 = 0;

/// A resolver plus the runtime that drives it and the lookups in flight.
pub struct DnsKmp {
    runtime: Runtime,
    resolver: TokioResolver,
    validate: bool,
    /// Running lookups and the cancels that arrived before their lookup did,
    /// under one lock so a cancel can never slip between the two.
    lookups: Mutex<Lookups>,
    /// Set by `dnskmp_shutdown`; lookups started afterwards fail at once.
    shut_down: AtomicBool,
}

#[derive(Default)]
struct Lookups {
    /// One cancel switch per running lookup, keyed by the id the caller chose.
    running: HashMap<u64, watch::Sender<bool>>,
    /// Ids cancelled before their lookup registered (the caller's cancel can
    /// run ahead of the lookup's own thread), oldest first. Bounded: past
    /// `MAX_EARLY_CANCELS` the oldest is forgotten and the lookup it meant runs
    /// to its timeout instead.
    cancelled_early: VecDeque<u64>,
}

const MAX_EARLY_CANCELS: usize = 1024;

/// Locks a mutex even if a panicking thread poisoned it; the guarded data is
/// always left consistent, so continuing beats aborting the host process.
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Config {
    upstreams: Vec<Upstream>,
    dnssec: bool,
    timeout_ms: u64,
    attempts: usize,
    cache_size: u64,
    ip_family: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Upstream {
    protocol: String,
    #[serde(default)]
    server_name: String,
    addresses: Vec<String>,
    #[serde(default)]
    path: String,
    port: u16,
}

thread_local! {
    static LAST_ERROR: RefCell<Option<CString>> = const { RefCell::new(None) };
}

fn set_error(message: impl std::fmt::Display) {
    let text = CString::new(message.to_string().replace('\0', " ")).unwrap_or_default();
    LAST_ERROR.with(|slot| *slot.borrow_mut() = Some(text));
}

/// Reads a required C string argument, recording an error when it is unusable.
unsafe fn arg_str<'a>(ptr: *const c_char, name: &str) -> Option<&'a str> {
    if ptr.is_null() {
        set_error(format!("{name} is null"));
        return None;
    }
    match CStr::from_ptr(ptr).to_str() {
        Ok(text) => Some(text),
        Err(_) => {
            set_error(format!("{name} is not valid UTF-8"));
            None
        }
    }
}

/// Opt-in diagnostics: `DNSKMP_LOG=<level>` prints hickory's tracing output to
/// stderr. Off unless the variable is set, so nothing about lookups is written
/// anywhere by default.
fn init_logging() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let Ok(level) = std::env::var("DNSKMP_LOG") else {
            return;
        };
        let level = level.parse().unwrap_or(tracing::Level::INFO);
        let _ = tracing_subscriber::fmt()
            .with_max_level(level)
            .with_writer(std::io::stderr)
            .try_init();
    });
}

fn parse_ip(text: &str) -> Result<IpAddr, String> {
    text.trim()
        .parse::<IpAddr>()
        .map_err(|_| "upstream address is not an IP address".to_owned())
}

fn name_servers(upstream: &Upstream) -> Result<Vec<NameServerConfig>, String> {
    if upstream.addresses.is_empty() {
        return Err("an upstream needs at least one IP address".to_owned());
    }
    let server_name: Arc<str> = Arc::from(upstream.server_name.as_str());
    let path: Option<Arc<str>> = if upstream.path.is_empty() {
        None
    } else {
        Some(Arc::from(upstream.path.as_str()))
    };
    let mut servers = Vec::with_capacity(upstream.addresses.len());
    for address in &upstream.addresses {
        let ip = parse_ip(address)?;
        let mut connections = match upstream.protocol.as_str() {
            "https" => vec![ConnectionConfig::https(server_name.clone(), path.clone())],
            "tls" => vec![ConnectionConfig::tls(server_name.clone())],
            "quic" => vec![ConnectionConfig::quic(server_name.clone())],
            "h3" => vec![ConnectionConfig::h3(server_name.clone(), path.clone())],
            "plain" => vec![ConnectionConfig::udp(), ConnectionConfig::tcp()],
            other => return Err(format!("unknown upstream protocol {other:?}")),
        };
        for connection in &mut connections {
            connection.port = upstream.port;
        }
        servers.push(NameServerConfig::new(ip, true, connections));
    }
    Ok(servers)
}

fn build(config: &Config) -> Result<(Runtime, TokioResolver), String> {
    let mut servers = Vec::new();
    for upstream in &config.upstreams {
        servers.extend(name_servers(upstream)?);
    }
    if servers.is_empty() {
        return Err("no upstreams configured".to_owned());
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .thread_name("dns-kmp")
        .enable_all()
        .build()
        .map_err(|error| format!("cannot start the resolver runtime: {error}"))?;

    let mut options = ResolverOpts::default();
    options.timeout = Duration::from_millis(config.timeout_ms.max(1));
    options.attempts = config.attempts.max(1);
    options.cache_size = config.cache_size;
    options.validate = config.dnssec;
    // The app's own file is not consulted: answers come from the upstreams only.
    options.use_hosts_file = ResolveHosts::Never;
    // 0x20 case randomization hardens plaintext UDP against spoofing. Encrypted
    // transports do not need it, and it would echo mixed-case owner names back.
    options.case_randomization = config
        .upstreams
        .iter()
        .any(|upstream| upstream.protocol == "plain");
    options.try_tcp_on_error = true;
    options.ip_strategy = match config.ip_family.as_str() {
        "ipv4" => LookupIpStrategy::Ipv4Only,
        "ipv6" => LookupIpStrategy::Ipv6Only,
        _ => LookupIpStrategy::Ipv4AndIpv6,
    };

    // The connection provider binds to the current runtime.
    let _guard = runtime.enter();
    let resolver = Resolver::builder_with_config(
        ResolverConfig::from_name_servers(servers),
        TokioRuntimeProvider::default(),
    )
    .with_options(options)
    .build()
    .map_err(|error| format!("cannot build the resolver: {error}"))?;
    Ok((runtime, resolver))
}

/// Creates a resolver from the JSON `DnsConfig.settingsJson()` produces.
/// Returns NULL and sets the last error if the configuration is unusable.
///
/// # Safety
/// `config` must be a valid NUL-terminated string or NULL.
#[no_mangle]
pub unsafe extern "C" fn dnskmp_create(config: *const c_char) -> *mut DnsKmp {
    init_logging();
    let Some(json) = arg_str(config, "config") else {
        return std::ptr::null_mut();
    };
    let config: Config = match serde_json::from_str(json) {
        Ok(config) => config,
        Err(error) => {
            set_error(format!("invalid resolver configuration: {error}"));
            return std::ptr::null_mut();
        }
    };
    match build(&config) {
        Ok((runtime, resolver)) => Box::into_raw(Box::new(DnsKmp {
            runtime,
            resolver,
            validate: config.dnssec,
            lookups: Mutex::new(Lookups::default()),
            shut_down: AtomicBool::new(false),
        })),
        Err(message) => {
            set_error(message);
            std::ptr::null_mut()
        }
    }
}

/// How a lookup failed, as the first line of the result text names it.
#[derive(Clone, Copy)]
enum Kind {
    NoRecords,
    Timeout,
    ServerFailure,
    Refused,
    Bogus,
    InvalidName,
    Cancelled,
    Other,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Kind::NoRecords => "NoRecords",
            Kind::Timeout => "Timeout",
            Kind::ServerFailure => "ServerFailure",
            Kind::Refused => "Refused",
            Kind::Bogus => "Bogus",
            Kind::InvalidName => "InvalidName",
            Kind::Cancelled => "Cancelled",
            Kind::Other => "Other",
        }
    }
}

/// The error and every cause beneath it, joined with ": ".
fn chain(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut cause = error.source();
    while let Some(next) = cause {
        let part = next.to_string();
        if !text.ends_with(&part) {
            text.push_str(": ");
            text.push_str(&part);
        }
        cause = next.source();
    }
    text
}

fn classify(error: &NetError) -> (Kind, String) {
    match error {
        NetError::Timeout => (Kind::Timeout, "no upstream answered in time".to_owned()),
        NetError::Dns(DnsError::NoRecordsFound(no_records)) => {
            let message = match no_records.response_code {
                ResponseCode::NXDomain => "the name does not exist",
                _ => "the name has no records of that type",
            };
            (Kind::NoRecords, message.to_owned())
        }
        NetError::Dns(DnsError::Nsec { .. }) => (
            Kind::NoRecords,
            "the name has no such records (proven by DNSSEC)".to_owned(),
        ),
        NetError::Dns(DnsError::ResponseCode(ResponseCode::Refused)) => {
            (Kind::Refused, "the upstream refused the query".to_owned())
        }
        NetError::Dns(DnsError::ResponseCode(code)) => (
            Kind::ServerFailure,
            format!("the upstream answered with an error: {code}"),
        ),
        NetError::Dns(DnsError::DnssecBogus) => {
            (Kind::Bogus, "DNSSEC validation failed".to_owned())
        }
        NetError::Proto(proto) => {
            let text = chain(proto);
            let lower = text.to_ascii_lowercase();
            if lower.contains("dnssec") || lower.contains("bogus") || lower.contains("rrsig") {
                (Kind::Bogus, format!("DNSSEC validation failed: {text}"))
            } else {
                (Kind::Other, text)
            }
        }
        other => (Kind::Other, chain(other)),
    }
}

/// Removes one spelling of the looked-up name from an error message (with or
/// without the trailing dot, any case); the caller applies it to every spelling
/// it knows (as given, ASCII/punycode, UTF-8), so the text is safe to log.
fn scrub(message: String, name: &str) -> String {
    let bare = name.trim_end_matches('.');
    if bare.is_empty() {
        return message;
    }
    let lower = message.to_ascii_lowercase();
    let needle = bare.to_ascii_lowercase();
    let mut out = String::with_capacity(message.len());
    let mut last = 0;
    let mut from = 0;
    while let Some(found) = lower[from..].find(&needle) {
        let start = from + found;
        let mut end = start + needle.len();
        if lower[end..].starts_with('.') {
            end += 1;
        }
        out.push_str(&message[last..start]);
        out.push_str("[name]");
        last = end;
        from = end;
    }
    out.push_str(&message[last..]);
    out
}

/// A field that cannot break the line or column structure of the result.
fn field(text: impl std::fmt::Display) -> String {
    text.to_string()
        .replace('\\', "\\\\")
        .replace('\t', "\\009")
        .replace('\n', "\\010")
        .replace('\r', "\\013")
}

/// Lays the answer out as text the Kotlin side parses without a JSON library:
///
/// ```text
/// OK<TAB>secure|insecure|unvalidated
/// <name><TAB><type code><TAB><ttl, u32><TAB><data>   (one line per record)
/// ```
///
/// or `ERR<TAB><kind><TAB><message>` on failure. Record data is hickory's
/// presentation of the record (`93.184.216.34`, `10 mail.example.com.`, and for
/// TXT the text itself with its strings concatenated, no quotes).
fn lookup_text(result: Result<Lookup, (Kind, String)>, validate: bool) -> String {
    match result {
        Err((kind, message)) => format!("ERR\t{}\t{}", kind.as_str(), field(message)),
        Ok(lookup) => {
            let records = lookup.answers();
            let security = if !validate {
                "unvalidated"
            } else if !records.is_empty()
                && records.iter().all(|record| record.proof == Proof::Secure)
            {
                "secure"
            } else {
                "insecure"
            };
            let mut text = format!("OK\t{security}");
            for record in records {
                text.push('\n');
                // Owner names are case-insensitive; present them in one case.
                text.push_str(&field(record.name.to_lowercase()));
                text.push('\t');
                text.push_str(&u16::from(record.record_type()).to_string());
                text.push('\t');
                text.push_str(&record.ttl.to_string());
                text.push('\t');
                text.push_str(&field(&record.data));
            }
            text
        }
    }
}

impl DnsKmp {
    /// Registers a lookup; `None` when it was cancelled before it got here.
    fn register(&self, id: u64) -> Option<watch::Receiver<bool>> {
        let mut lookups = lock(&self.lookups);
        if let Some(position) = lookups.cancelled_early.iter().position(|&early| early == id) {
            lookups.cancelled_early.remove(position);
            return None;
        }
        let (sender, receiver) = watch::channel(false);
        lookups.running.insert(id, sender);
        Some(receiver)
    }

    fn unregister(&self, id: u64) {
        lock(&self.lookups).running.remove(&id);
    }

    fn cancel(&self, id: u64) {
        let mut lookups = lock(&self.lookups);
        if let Some(sender) = lookups.running.get(&id) {
            let _ = sender.send(true);
            return;
        }
        if lookups.cancelled_early.contains(&id) {
            return;
        }
        if lookups.cancelled_early.len() >= MAX_EARLY_CANCELS {
            lookups.cancelled_early.pop_front();
        }
        lookups.cancelled_early.push_back(id);
    }

    fn cancel_all(&self) {
        for sender in lock(&self.lookups).running.values() {
            let _ = sender.send(true);
        }
    }

    fn resolve(&self, id: u64, name: &str, record_type: u16) -> Result<Lookup, (Kind, String)> {
        if self.shut_down.load(Ordering::SeqCst) {
            return Err((Kind::Cancelled, "the resolver is closed".to_owned()));
        }
        let parsed = Name::from_utf8(name)
            .map_err(|_| (Kind::InvalidName, "not a valid DNS name".to_owned()))?;
        let Some(mut cancel) = self.register(id) else {
            return Err((Kind::Cancelled, "the lookup was cancelled".to_owned()));
        };
        if self.shut_down.load(Ordering::SeqCst) {
            self.unregister(id);
            return Err((Kind::Cancelled, "the resolver is closed".to_owned()));
        }
        let resolver = &self.resolver;
        let result = self.runtime.block_on(async {
            let lookup = async {
                if record_type == IP_LOOKUP {
                    // lookup_ip answers an IP literal without a query and
                    // follows the configured family strategy.
                    resolver.lookup_ip(name).await.map(|ip| ip.as_lookup().clone())
                } else {
                    resolver.lookup(parsed.clone(), RecordType::from(record_type)).await
                }
            };
            tokio::select! {
                result = lookup => result.map_err(|error| classify(&error)),
                _ = cancel.wait_for(|cancelled| *cancelled) => {
                    Err((Kind::Cancelled, "the lookup was cancelled".to_owned()))
                }
            }
        });
        self.unregister(id);
        result.map_err(|(kind, message)| {
            let message = scrub(message, name);
            let message = scrub(message, &parsed.to_ascii());
            (kind, scrub(message, &parsed.to_utf8()))
        })
    }
}

/// Resolves `name`. `record_type` is a DNS type code, or [`IP_LOOKUP`] for
/// addresses. `id` identifies the call for `dnskmp_cancel`; the caller picks a
/// value not shared with another lookup on the same resolver. Returns the text
/// described at [`lookup_text`], to free with `dnskmp_string_free`, or NULL
/// (last error set) for a misuse of the ABI.
///
/// # Safety
/// `resolver` must come from `dnskmp_create` and not have been destroyed;
/// `name` must be a valid NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn dnskmp_lookup(
    resolver: *const DnsKmp,
    id: u64,
    name: *const c_char,
    record_type: u16,
) -> *mut c_char {
    if resolver.is_null() {
        set_error("resolver is null");
        return std::ptr::null_mut();
    }
    let Some(name) = arg_str(name, "name") else {
        return std::ptr::null_mut();
    };
    let text = lookup_text((*resolver).resolve(id, name, record_type), (*resolver).validate);
    CString::new(text.replace('\0', " "))
        .map(CString::into_raw)
        .unwrap_or(std::ptr::null_mut())
}

/// Makes the lookup registered under `id` return at once with `Cancelled`.
/// Unknown ids are ignored.
///
/// # Safety
/// `resolver` must come from `dnskmp_create` and not have been destroyed.
#[no_mangle]
pub unsafe extern "C" fn dnskmp_cancel(resolver: *const DnsKmp, id: u64) {
    if let Some(resolver) = resolver.as_ref() {
        resolver.cancel(id);
    }
}

/// Cancels every running lookup and refuses new ones. Safe to call more than once.
///
/// # Safety
/// `resolver` must come from `dnskmp_create` and not have been destroyed.
#[no_mangle]
pub unsafe extern "C" fn dnskmp_shutdown(resolver: *const DnsKmp) {
    if let Some(resolver) = resolver.as_ref() {
        resolver.shut_down.store(true, Ordering::SeqCst);
        resolver.cancel_all();
    }
}

/// Forgets every cached answer.
///
/// # Safety
/// `resolver` must come from `dnskmp_create` and not have been destroyed.
#[no_mangle]
pub unsafe extern "C" fn dnskmp_clear_cache(resolver: *const DnsKmp) {
    if let Some(resolver) = resolver.as_ref() {
        resolver.resolver.clear_cache();
    }
}

/// Frees the resolver. No call may be in flight.
///
/// # Safety
/// `resolver` must come from `dnskmp_create` and must not be used afterwards.
#[no_mangle]
pub unsafe extern "C" fn dnskmp_destroy(resolver: *mut DnsKmp) {
    if !resolver.is_null() {
        drop(Box::from_raw(resolver));
    }
}

/// The reason the last call on this thread failed, or NULL. Free with
/// `dnskmp_string_free`.
#[no_mangle]
pub extern "C" fn dnskmp_last_error() -> *mut c_char {
    LAST_ERROR.with(|slot| {
        slot.borrow_mut()
            .take()
            .map(CString::into_raw)
            .unwrap_or(std::ptr::null_mut())
    })
}

/// Frees a string returned by this library.
///
/// # Safety
/// `text` must have been returned by this library and not freed before.
#[no_mangle]
pub unsafe extern "C" fn dnskmp_string_free(text: *mut c_char) {
    if !text.is_null() {
        drop(CString::from_raw(text));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrub_removes_every_spelling_of_the_name() {
        let text = "no records for Example.COM. and example.com, really".to_owned();
        assert_eq!(
            scrub(text, "example.com."),
            "no records for [name] and [name], really"
        );
    }

    #[test]
    fn scrub_leaves_other_text_alone() {
        assert_eq!(scrub("timeout".to_owned(), "example.com"), "timeout");
        assert_eq!(scrub("x".to_owned(), "."), "x");
    }

    #[test]
    fn a_cancel_that_arrives_first_is_remembered_once() {
        let (runtime, resolver) = build(&Config {
            upstreams: vec![Upstream {
                protocol: "tls".into(),
                server_name: "blackhole.invalid".into(),
                addresses: vec!["192.0.2.1".into()],
                path: String::new(),
                port: 853,
            }],
            dnssec: false,
            timeout_ms: 1000,
            attempts: 1,
            cache_size: 0,
            ip_family: "both".into(),
        })
        .unwrap();
        let dns = DnsKmp {
            runtime,
            resolver,
            validate: false,
            lookups: Mutex::new(Lookups::default()),
            shut_down: AtomicBool::new(false),
        };
        dns.cancel(7);
        dns.cancel(7);
        assert!(dns.register(7).is_none());
        assert!(dns.register(7).is_some());
        dns.unregister(7);

        // Past the cap the oldest early cancel is the one forgotten.
        for id in 0..MAX_EARLY_CANCELS as u64 + 1 {
            dns.cancel(1000 + id);
        }
        assert!(dns.register(1000).is_some());
        dns.unregister(1000);
        assert!(dns.register(1001).is_none());
        assert!(dns.register(1000 + MAX_EARLY_CANCELS as u64).is_none());
    }

    #[test]
    fn field_escapes_separators() {
        assert_eq!(field("a\tb\nc\\d"), "a\\009b\\010c\\\\d");
    }

    #[test]
    fn unknown_protocol_is_rejected() {
        let upstream = Upstream {
            protocol: "smoke".into(),
            server_name: String::new(),
            addresses: vec!["1.1.1.1".into()],
            path: String::new(),
            port: 53,
        };
        assert!(name_servers(&upstream).is_err());
    }

    #[test]
    fn every_address_becomes_a_server() {
        let upstream = Upstream {
            protocol: "https".into(),
            server_name: "cloudflare-dns.com".into(),
            addresses: vec!["1.1.1.1".into(), "2606:4700:4700::1111".into()],
            path: "/dns-query".into(),
            port: 443,
        };
        let servers = name_servers(&upstream).unwrap();
        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0].connections[0].port, 443);
    }
}
