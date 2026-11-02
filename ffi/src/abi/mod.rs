//! The `extern "C"` surface of `include/vardevall.h`.

#![allow(non_camel_case_types, clippy::missing_safety_doc)]

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;

use vardevall_tun::config::{Config, Context};
use vardevall_tun::embed::{self, Callbacks, MAX_NETWORKS, NetworkSpec};
use vardevall_tun::keys;

use crate::host::{self, DEFAULT_NETWORK, Host};

/// IP packets for the tunnel to write, in order, in one call; the first nibble is the version.
pub type vv_packets_cb = Option<
    unsafe extern "C" fn(ctx: *mut c_void, packets: *const *const u8, lens: *const usize, n: usize),
>;
/// A JSON event.
pub type vv_event_cb = Option<unsafe extern "C" fn(ctx: *mut c_void, json: *const c_char)>;
/// A JSON mDNS request for the Bonjour backend.
pub type vv_mdns_cb = Option<unsafe extern "C" fn(ctx: *mut c_void, json: *const c_char)>;

/// An engine instance.
pub struct VvHandle {
    host: Host,
}

#[derive(Clone, Copy)]
struct Ctx(*mut c_void);

// SAFETY: the caller of `vv_start` guarantees `ctx` may be used from any thread.
unsafe impl Send for Ctx {}
unsafe impl Sync for Ctx {}

impl Ctx {
    fn get(self) -> *mut c_void {
        self.0
    }
}

fn set_err(err_out: *mut *mut c_char, msg: &str) {
    if err_out.is_null() {
        return;
    }
    let s = CString::new(msg.replace('\0', " ")).unwrap_or_default();
    // SAFETY: `err_out` is non-null and points to writable storage per the header.
    unsafe { *err_out = s.into_raw() };
}

fn into_c(s: &str) -> *mut c_char {
    CString::new(s.replace('\0', " "))
        .unwrap_or_default()
        .into_raw()
}

unsafe fn text<'a>(p: *const c_char) -> Result<&'a str, String> {
    if p.is_null() {
        return Err("null string".into());
    }
    // SAFETY: the caller passes a NUL-terminated string valid for the call.
    unsafe { CStr::from_ptr(p) }
        .to_str()
        .map_err(|_| "string is not UTF-8".to_string())
}

fn guard<T>(err_out: *mut *mut c_char, fail: T, f: impl FnOnce() -> Result<T, String>) -> T {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            set_err(err_out, &e);
            fail
        }
        Err(_) => {
            set_err(err_out, "internal error");
            fail
        }
    }
}

/// `n` names and configs as the specs of the networks.
///
/// # Safety
/// `names` and `configs` point to `n` NUL-terminated strings each, valid for the call.
unsafe fn specs(
    names: *const *const c_char,
    configs: *const *const c_char,
    n: usize,
) -> Result<Vec<NetworkSpec>, String> {
    if names.is_null() || configs.is_null() || n == 0 || n > MAX_NETWORKS {
        return Err(format!("between 1 and {MAX_NETWORKS} networks are needed"));
    }
    // SAFETY: both arrays are readable for `n` elements per the header.
    let (names, configs) = unsafe {
        (
            std::slice::from_raw_parts(names, n),
            std::slice::from_raw_parts(configs, n),
        )
    };
    names
        .iter()
        .zip(configs)
        .map(|(&name, &config)| {
            // SAFETY: each element is a NUL-terminated string per the header.
            let (name, config_toml) = unsafe { (text(name)?, text(config)?) };
            Ok(NetworkSpec {
                name: name.to_owned(),
                config_toml: config_toml.to_owned(),
            })
        })
        .collect()
}

/// A network named by an optional string: `None` for the first.
///
/// # Safety
/// `network` is NULL or a NUL-terminated string valid for the call.
unsafe fn network<'a>(network: *const c_char) -> Result<Option<&'a str>, String> {
    if network.is_null() {
        return Ok(None);
    }
    // SAFETY: forwarded from the caller's contract.
    unsafe { text(network) }.map(Some)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn vv_start(
    config_toml: *const c_char,
    on_packets: vv_packets_cb,
    on_event: vv_event_cb,
    on_mdns: vv_mdns_cb,
    ctx: *mut c_void,
    err_out: *mut *mut c_char,
) -> *mut VvHandle {
    guard(err_out, ptr::null_mut(), || {
        // SAFETY: forwarded from the caller's contract.
        let config = unsafe { text(config_toml) }?;
        let spec = NetworkSpec {
            name: DEFAULT_NETWORK.to_owned(),
            config_toml: config.to_owned(),
        };
        start(vec![spec], on_packets, on_event, on_mdns, ctx)
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn vv_start_networks(
    names: *const *const c_char,
    configs: *const *const c_char,
    n: usize,
    on_packets: vv_packets_cb,
    on_event: vv_event_cb,
    on_mdns: vv_mdns_cb,
    ctx: *mut c_void,
    err_out: *mut *mut c_char,
) -> *mut VvHandle {
    guard(err_out, ptr::null_mut(), || {
        // SAFETY: forwarded from the caller's contract.
        let specs = unsafe { specs(names, configs, n) }?;
        start(specs, on_packets, on_event, on_mdns, ctx)
    })
}

/// Starts the engine for the networks of `specs` with the host's callbacks.
fn start(
    specs: Vec<NetworkSpec>,
    on_packets: vv_packets_cb,
    on_event: vv_event_cb,
    on_mdns: vv_mdns_cb,
    ctx: *mut c_void,
) -> Result<*mut VvHandle, String> {
    let on_packets = on_packets.ok_or("on_packets is required")?;
    let on_event = on_event.ok_or("on_event is required")?;
    let ctx = Ctx(ctx);
    let callbacks = Callbacks {
        // SAFETY (all three): the callbacks and `ctx` are valid until `vv_stop` returns, and
        // the engine runs none afterwards. The arrays outlive the call that reads them.
        packets: Box::new(move |packets| {
            let ptrs: Vec<*const u8> = packets.iter().map(|p| p.as_ptr()).collect();
            let lens: Vec<usize> = packets.iter().map(|p| p.len()).collect();
            unsafe { on_packets(ctx.get(), ptrs.as_ptr(), lens.as_ptr(), packets.len()) }
        }),
        event: Box::new(move |network, e| {
            if let Ok(c) = CString::new(e.to_json(network)) {
                unsafe { on_event(ctx.get(), c.as_ptr()) }
            }
        }),
        mdns: on_mdns.map(|cb| -> embed::MdnsFn {
            Box::new(move |r| {
                if let Ok(c) = CString::new(embed::request_to_json(r)) {
                    unsafe { cb(ctx.get(), c.as_ptr()) }
                }
            })
        }),
    };
    let host = host::start(specs, callbacks)?;
    Ok(Box::into_raw(Box::new(VvHandle { host })))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn vv_stop(handle: *mut VvHandle) {
    if handle.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: `handle` came from `vv_start` and is not used again.
        unsafe { Box::from_raw(handle) }.host.stop();
    }));
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn vv_packets_in(
    handle: *mut VvHandle,
    packets: *const *const u8,
    lens: *const usize,
    n: usize,
) {
    if handle.is_null() || packets.is_null() || lens.is_null() || n == 0 {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: the handle is live, and `packets` and `lens` are readable for `n` elements.
        let (h, ptrs, lens) = unsafe {
            (
                &*handle,
                std::slice::from_raw_parts(packets, n),
                std::slice::from_raw_parts(lens, n),
            )
        };
        h.host.networks().packets_in(
            ptrs.iter()
                .zip(lens)
                .filter(|(p, _)| !p.is_null())
                // SAFETY: a non-NULL entry is readable for its length.
                .map(|(&p, &len)| unsafe { std::slice::from_raw_parts(p, len) }),
        );
    }));
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn vv_path_changed(handle: *mut VvHandle, json: *const c_char) {
    if handle.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: the handle is live and a non-NULL `json` is a NUL-terminated string.
        let h = unsafe { &*handle };
        let update = unsafe { text(json) }
            .ok()
            .and_then(|j| embed::path_update_from_json(j).ok());
        match update {
            Some(u) => h.host.networks().path_update(&u),
            None => h.host.networks().path_changed(),
        }
    }));
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn vv_announce(
    handle: *mut VvHandle,
    network_name: *const c_char,
    name: *const c_char,
    port: u16,
    proto: *const c_char,
    err_out: *mut *mut c_char,
) -> c_int {
    guard(err_out, -1, || {
        if handle.is_null() {
            return Err("null handle".into());
        }
        // SAFETY: the handle is live and the strings are NUL-terminated per the header.
        let (h, net, name, proto) =
            unsafe { (&*handle, network(network_name)?, text(name)?, text(proto)?) };
        let proto = embed::proto_from_str(proto).ok_or("proto must be \"tcp\" or \"udp\"")?;
        h.host
            .networks()
            .announce(net, name, port, proto)
            .map_err(|e| e.to_string())?;
        Ok(0)
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn vv_withdraw(
    handle: *mut VvHandle,
    network_name: *const c_char,
    name: *const c_char,
) -> c_int {
    if handle.is_null() {
        return 0;
    }
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: the handle is live and non-NULL strings are NUL-terminated.
        let h = unsafe { &*handle };
        match unsafe { (network(network_name), text(name)) } {
            (Ok(net), Ok(name)) => i32::from(h.host.networks().withdraw(net, name)),
            _ => 0,
        }
    }))
    .unwrap_or(0)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn vv_providers(
    handle: *mut VvHandle,
    network_name: *const c_char,
    name: *const c_char,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    guard(err_out, ptr::null_mut(), || {
        if handle.is_null() {
            return Err("null handle".into());
        }
        // SAFETY: the handle is live and the strings are NUL-terminated.
        let (h, net, name) = unsafe { (&*handle, network(network_name)?, text(name)?) };
        let json = h
            .host
            .networks()
            .providers_json(net, name)
            .map_err(|e| e.to_string())?;
        Ok(into_c(&json))
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn vv_set_exit(
    handle: *mut VvHandle,
    network_name: *const c_char,
    site: *const c_char,
    err_out: *mut *mut c_char,
) -> c_int {
    guard(err_out, -1, || {
        if handle.is_null() {
            return Err("null handle".into());
        }
        // SAFETY: the handle is live and non-NULL strings are NUL-terminated per the header.
        let h = unsafe { &*handle };
        let exit = match unsafe { network(network_name)? } {
            None => None,
            Some(name) => {
                let site = if site.is_null() {
                    None
                } else {
                    // SAFETY: as above.
                    Some(unsafe { text(site) }?.parse().map_err(|e| format!("{e}"))?)
                };
                Some((name, embed::ExitUse { site }))
            }
        };
        h.host
            .networks()
            .set_exit(exit)
            .map_err(|e| e.to_string())?;
        Ok(0)
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn vv_remember_exits(
    handle: *mut VvHandle,
    network_name: *const c_char,
    json: *const c_char,
    err_out: *mut *mut c_char,
) -> c_int {
    guard(err_out, -1, || {
        if handle.is_null() {
            return Err("null handle".into());
        }
        // SAFETY: the handle is live and the strings are NUL-terminated per the header.
        let (h, net, json) = unsafe { (&*handle, network(network_name)?, text(json)?) };
        let offers = embed::exits_from_json(json).map_err(|e| e.to_string())?;
        h.host
            .networks()
            .remember_exits(net, offers)
            .map_err(|e| e.to_string())?;
        Ok(0)
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn vv_exit_in_use(
    handle: *mut VvHandle,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    guard(err_out, ptr::null_mut(), || {
        if handle.is_null() {
            return Err("null handle".into());
        }
        // SAFETY: the handle is live.
        let h = unsafe { &*handle };
        Ok(into_c(&h.host.networks().exit_in_use_json()))
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn vv_mdns_event(handle: *mut VvHandle, json: *const c_char) {
    if handle.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: the handle is live and `json` is a NUL-terminated string.
        let (h, j) = unsafe { (&*handle, text(json)) };
        if let Ok(event) = j
            .map_err(drop)
            .and_then(|j| embed::event_from_json(j).map_err(drop))
        {
            h.host.networks().mdns_event(event);
        }
    }));
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn vv_tunnel_settings(
    config_toml: *const c_char,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    guard(err_out, ptr::null_mut(), || {
        // SAFETY: forwarded from the caller's contract.
        let t = embed::tunnel_settings(unsafe { text(config_toml) }?, &Context::default())
            .map_err(|e| e.to_string())?;
        Ok(into_c(&t.to_json()))
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn vv_tunnel_settings_networks(
    names: *const *const c_char,
    configs: *const *const c_char,
    n: usize,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    guard(err_out, ptr::null_mut(), || {
        // SAFETY: forwarded from the caller's contract.
        let specs = unsafe { specs(names, configs, n) }?;
        let t = embed::tunnel_settings_networks(&specs).map_err(|e| e.to_string())?;
        Ok(into_c(&t.to_json()))
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn vv_generate_node_key(err_out: *mut *mut c_char) -> *mut c_char {
    guard(err_out, ptr::null_mut(), || {
        Ok(into_c(&keys::generate_node_key()))
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn vv_generate_network_secret(err_out: *mut *mut c_char) -> *mut c_char {
    guard(err_out, ptr::null_mut(), || {
        Ok(into_c(&keys::generate_network_secret()))
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn vv_public_key(
    secret: *const c_char,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    guard(err_out, ptr::null_mut(), || {
        // SAFETY: forwarded from the caller's contract.
        let pk = keys::public_key(unsafe { text(secret) }?).map_err(|e| e.to_string())?;
        Ok(into_c(&pk))
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn vv_validate_config(
    config_toml: *const c_char,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    guard(err_out, ptr::null_mut(), || {
        // SAFETY: forwarded from the caller's contract.
        let c = Config::parse(unsafe { text(config_toml) }?, &Context::default())
            .map_err(|e| e.to_string())?;
        Ok(into_c(&c.summary().to_string()))
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn vv_string_free(s: *mut c_char) {
    if !s.is_null() {
        // SAFETY: `s` was returned by this library and is freed once.
        drop(unsafe { CString::from_raw(s) });
    }
}

#[cfg(test)]
mod tests;
