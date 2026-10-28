//! JNI entry points for `io.github.androidpoet.dns.internal.DnsBridge` on the
//! JVM and Android. Each one forwards to the C ABI and turns an ABI failure into
//! a `DnsException`.

use std::ffi::{CStr, CString};
use std::ptr;

use jni::objects::{JClass, JString};
use jni::sys::{jint, jlong, jstring};
use jni::JNIEnv;

use crate::*;

const DNS_EXCEPTION: &str = "io/github/androidpoet/dns/DnsException";

fn throw(env: &mut JNIEnv, message: &str) {
    // Fails only if an exception is already pending, which is what we want anyway.
    let _ = env.throw_new(DNS_EXCEPTION, message);
}

fn throw_last_error(env: &mut JNIEnv) {
    let message = unsafe {
        let text = dnskmp_last_error();
        if text.is_null() {
            "unknown native error".to_owned()
        } else {
            let owned = CStr::from_ptr(text).to_string_lossy().into_owned();
            dnskmp_string_free(text);
            owned
        }
    };
    throw(env, &message);
}

/// Copies a Java string into a C string, throwing on failure.
fn c_string(env: &mut JNIEnv, value: &JString) -> Option<CString> {
    let text: String = match env.get_string(value) {
        Ok(text) => text.into(),
        Err(_) => {
            throw(env, "invalid string argument");
            return None;
        }
    };
    match CString::new(text) {
        Ok(text) => Some(text),
        Err(_) => {
            throw(env, "string argument contains NUL");
            None
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_io_github_androidpoet_dns_internal_DnsBridge_create(
    mut env: JNIEnv,
    _class: JClass,
    config: JString,
) -> jlong {
    let Some(config) = c_string(&mut env, &config) else {
        return 0;
    };
    let resolver = unsafe { dnskmp_create(config.as_ptr()) };
    if resolver.is_null() {
        throw_last_error(&mut env);
    }
    resolver as jlong
}

#[no_mangle]
pub extern "system" fn Java_io_github_androidpoet_dns_internal_DnsBridge_lookup(
    mut env: JNIEnv,
    _class: JClass,
    resolver: jlong,
    id: jlong,
    name: JString,
    record_type: jint,
) -> jstring {
    let Some(name) = c_string(&mut env, &name) else {
        return ptr::null_mut();
    };
    unsafe {
        let text = dnskmp_lookup(
            resolver as *const DnsKmp,
            id as u64,
            name.as_ptr(),
            record_type as u16,
        );
        if text.is_null() {
            throw_last_error(&mut env);
            return ptr::null_mut();
        }
        let owned = CStr::from_ptr(text).to_string_lossy().into_owned();
        dnskmp_string_free(text);
        env.new_string(owned)
            .map(|s| s.into_raw())
            .unwrap_or(ptr::null_mut())
    }
}

#[no_mangle]
pub extern "system" fn Java_io_github_androidpoet_dns_internal_DnsBridge_cancel(
    _env: JNIEnv,
    _class: JClass,
    resolver: jlong,
    id: jlong,
) {
    unsafe { dnskmp_cancel(resolver as *const DnsKmp, id as u64) }
}

#[no_mangle]
pub extern "system" fn Java_io_github_androidpoet_dns_internal_DnsBridge_shutdown(
    _env: JNIEnv,
    _class: JClass,
    resolver: jlong,
) {
    unsafe { dnskmp_shutdown(resolver as *const DnsKmp) }
}

#[no_mangle]
pub extern "system" fn Java_io_github_androidpoet_dns_internal_DnsBridge_clearCache(
    _env: JNIEnv,
    _class: JClass,
    resolver: jlong,
) {
    unsafe { dnskmp_clear_cache(resolver as *const DnsKmp) }
}

#[no_mangle]
pub extern "system" fn Java_io_github_androidpoet_dns_internal_DnsBridge_destroy(
    _env: JNIEnv,
    _class: JClass,
    resolver: jlong,
) {
    unsafe { dnskmp_destroy(resolver as *mut DnsKmp) }
}
