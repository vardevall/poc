//! The `Java_dev_vardevall_Native_*` functions: `Native.kt` is the authority for their names and
//! parameters, as `include/vardevall.h` is for the C interface of the Apple apps.

#![allow(non_snake_case, clippy::missing_safety_doc)]

use std::net::SocketAddr;
use std::os::fd::{FromRawFd, OwnedFd};
use std::panic::{AssertUnwindSafe, catch_unwind};

use jni::JNIEnv;
use jni::objects::{JByteArray, JObject, JObjectArray, JString};
use jni::sys::{jboolean, jint, jlong, jstring};
use vardevall_tun::config::{Config, Context};
use vardevall_tun::embed::{self, ExitUse, MAX_NETWORKS, NetworkSpec};
use vardevall_tun::keys;

use crate::bridge::Bridge;
use crate::engine::{Engine, Sinks};
use crate::resolvers;

/// Name of the network of `vvStart`, which gives the default domain `vardevall.internal`.
const DEFAULT_NETWORK: &str = "vardevall";
const EXCEPTION: &str = "dev/vardevall/VvException";

fn throw(env: &mut JNIEnv, message: &str) {
    if !env.exception_check().unwrap_or(false) {
        let _ = env.throw_new(EXCEPTION, message);
    }
}

/// Runs `f`; an error or a panic becomes a `VvException` and the result `fail`.
fn guard<T>(env: &mut JNIEnv, fail: T, f: impl FnOnce(&mut JNIEnv) -> Result<T, String>) -> T {
    match catch_unwind(AssertUnwindSafe(|| f(env))) {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            throw(env, &e);
            fail
        }
        Err(_) => {
            throw(env, "internal error");
            fail
        }
    }
}

fn string(env: &mut JNIEnv, s: &JString) -> Result<String, String> {
    if s.is_null() {
        return Err("null string".into());
    }
    env.get_string(s)
        .map(String::from)
        .map_err(|e| e.to_string())
}

fn optional(env: &mut JNIEnv, s: &JString) -> Result<Option<String>, String> {
    if s.is_null() {
        Ok(None)
    } else {
        string(env, s).map(Some)
    }
}

fn strings(env: &mut JNIEnv, array: &JObjectArray) -> Result<Vec<String>, String> {
    if array.is_null() {
        return Err("null array".into());
    }
    let n = env.get_array_length(array).map_err(|e| e.to_string())?;
    (0..n)
        .map(|i| {
            let element = env
                .get_object_array_element(array, i)
                .map_err(|e| e.to_string())?;
            string(env, &JString::from(element))
        })
        .collect()
}

fn output(env: &mut JNIEnv, text: &str) -> Result<jstring, String> {
    env.new_string(text)
        .map(JString::into_raw)
        .map_err(|e| e.to_string())
}

fn specs(
    env: &mut JNIEnv,
    names: &JObjectArray,
    configs: &JObjectArray,
) -> Result<Vec<NetworkSpec>, String> {
    let (names, configs) = (strings(env, names)?, strings(env, configs)?);
    if names.len() != configs.len() || names.is_empty() || names.len() > MAX_NETWORKS {
        return Err(format!("between 1 and {MAX_NETWORKS} networks are needed"));
    }
    Ok(names
        .into_iter()
        .zip(configs)
        .map(|(name, config_toml)| NetworkSpec { name, config_toml })
        .collect())
}

/// The engine of a handle `vvStart` returned.
fn engine<'a>(handle: jlong) -> Result<&'a Engine, String> {
    if handle == 0 {
        return Err("null handle".into());
    }
    // SAFETY: Kotlin passes only handles that `start` returned and `vvStop` has not freed, and
    // calls no function with a handle during or after `vvStop`.
    Ok(unsafe { &*(handle as *const Engine) })
}

/// The descriptor Kotlin gave away with `detachFd()`. It is taken at once, so that a call that
/// fails closes it.
fn owned(fd: jint) -> Result<OwnedFd, String> {
    if fd < 0 {
        return Err("no interface".into());
    }
    // SAFETY: Kotlin gives the descriptor away; nothing else closes it.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn start(
    env: &mut JNIEnv,
    specs: Vec<NetworkSpec>,
    fd: Result<OwnedFd, String>,
    callbacks: &JObject,
    external_mdns: bool,
) -> Result<jlong, String> {
    let engine = Engine::start(specs, fd?, sinks(env, callbacks, external_mdns)?)?;
    Ok(Box::into_raw(Box::new(engine)) as jlong)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_vardevall_Native_vvStart<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    config: JString<'l>,
    tun_fd: jint,
    callbacks: JObject<'l>,
    external_mdns: jboolean,
) -> jlong {
    let fd = owned(tun_fd);
    guard(&mut env, 0, |env| {
        let spec = NetworkSpec {
            name: DEFAULT_NETWORK.to_owned(),
            config_toml: string(env, &config)?,
        };
        start(env, vec![spec], fd, &callbacks, external_mdns != 0)
    })
}

fn sinks(env: &mut JNIEnv, callbacks: &JObject, external_mdns: bool) -> Result<Sinks, String> {
    let bridge = Bridge::new(env, callbacks).map_err(|e| e.to_string())?;
    let (events, requests) = (bridge.clone(), bridge);
    Ok(Sinks {
        event: Box::new(move |json| events.deliver("onEvent", json)),
        mdns: external_mdns.then(|| -> crate::engine::Sink {
            Box::new(move |json| requests.deliver("onMdns", json))
        }),
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_vardevall_Native_vvStartNetworks<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    names: JObjectArray<'l>,
    configs: JObjectArray<'l>,
    tun_fd: jint,
    callbacks: JObject<'l>,
    external_mdns: jboolean,
) -> jlong {
    let fd = owned(tun_fd);
    guard(&mut env, 0, |env| {
        let specs = specs(env, &names, &configs)?;
        start(env, specs, fd, &callbacks, external_mdns != 0)
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_vardevall_Native_vvStop<'l>(
    _env: JNIEnv<'l>,
    _this: JObject<'l>,
    handle: jlong,
) {
    if handle == 0 {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: `handle` came from `start` and Kotlin uses it no more.
        unsafe { Box::from_raw(handle as *mut Engine) }.stop();
    }));
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_vardevall_Native_vvSetTun<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    handle: jlong,
    tun_fd: jint,
) {
    let fd = owned(tun_fd);
    guard(&mut env, (), |_| {
        engine(handle)?
            .set_tun(fd?)
            .map_err(|e| format!("interface: {e}"))
    });
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_vardevall_Native_vvSetResolvers<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    handle: jlong,
    servers: JObjectArray<'l>,
) {
    guard(&mut env, (), |env| {
        let list: Vec<SocketAddr> = strings(env, &servers)?
            .iter()
            .filter_map(|s| resolvers::parse(s))
            .collect();
        engine(handle)?.set_resolvers(&list);
        Ok(())
    });
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_vardevall_Native_vvPacketsIn<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    handle: jlong,
    packets: JObjectArray<'l>,
) {
    guard(&mut env, (), |env| {
        let n = env.get_array_length(&packets).map_err(|e| e.to_string())?;
        let mut batch = Vec::new();
        for i in 0..n {
            let element = env
                .get_object_array_element(&packets, i)
                .map_err(|e| e.to_string())?;
            if element.is_null() {
                continue;
            }
            let bytes = env
                .convert_byte_array(JByteArray::from(element))
                .map_err(|e| e.to_string())?;
            batch.push(bytes);
        }
        engine(handle)?
            .networks()
            .packets_in(batch.iter().map(Vec::as_slice));
        Ok(())
    });
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_vardevall_Native_vvPathChanged<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    handle: jlong,
    json: JString<'l>,
) {
    guard(&mut env, (), |env| {
        let networks = engine(handle)?.networks();
        let update = optional(env, &json)?.and_then(|j| embed::path_update_from_json(&j).ok());
        match update {
            Some(u) => networks.path_update(&u),
            None => networks.path_changed(),
        }
        Ok(())
    });
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_vardevall_Native_vvAnnounce<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    handle: jlong,
    network: JString<'l>,
    name: JString<'l>,
    port: jint,
    proto: JString<'l>,
) {
    guard(&mut env, (), |env| {
        let (network, name, proto) = (
            optional(env, &network)?,
            string(env, &name)?,
            string(env, &proto)?,
        );
        let port = u16::try_from(port).map_err(|_| "invalid port".to_owned())?;
        let proto =
            embed::proto_from_str(&proto).ok_or("proto must be \"tcp\" or \"udp\"".to_owned())?;
        engine(handle)?
            .networks()
            .announce(network.as_deref(), &name, port, proto)
            .map_err(|e| e.to_string())
    });
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_vardevall_Native_vvWithdraw<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    handle: jlong,
    network: JString<'l>,
    name: JString<'l>,
) -> jboolean {
    guard(&mut env, 0, |env| {
        let (network, name) = (optional(env, &network)?, string(env, &name)?);
        Ok(jboolean::from(
            engine(handle)?
                .networks()
                .withdraw(network.as_deref(), &name),
        ))
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_vardevall_Native_vvProviders<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    handle: jlong,
    network: JString<'l>,
    name: JString<'l>,
) -> jstring {
    guard(&mut env, std::ptr::null_mut(), |env| {
        let (network, name) = (optional(env, &network)?, string(env, &name)?);
        let json = engine(handle)?
            .networks()
            .providers_json(network.as_deref(), &name)
            .map_err(|e| e.to_string())?;
        output(env, &json)
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_vardevall_Native_vvSetExit<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    handle: jlong,
    network: JString<'l>,
    site: JString<'l>,
) {
    guard(&mut env, (), |env| {
        let (network, site) = (optional(env, &network)?, optional(env, &site)?);
        let exit = match network.as_deref() {
            None => None,
            Some(name) => {
                let site = site
                    .map(|s| s.parse().map_err(|e| format!("{e}")))
                    .transpose()?;
                Some((name, ExitUse { site }))
            }
        };
        engine(handle)?
            .networks()
            .set_exit(exit)
            .map_err(|e| e.to_string())
    });
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_vardevall_Native_vvRememberExits<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    handle: jlong,
    network: JString<'l>,
    json: JString<'l>,
) {
    guard(&mut env, (), |env| {
        let (network, json) = (optional(env, &network)?, string(env, &json)?);
        let offers = embed::exits_from_json(&json).map_err(|e| e.to_string())?;
        engine(handle)?
            .networks()
            .remember_exits(network.as_deref(), offers)
            .map_err(|e| e.to_string())
    });
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_vardevall_Native_vvExitInUse<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    handle: jlong,
) -> jstring {
    guard(&mut env, std::ptr::null_mut(), |env| {
        let json = engine(handle)?.networks().exit_in_use_json();
        output(env, &json)
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_vardevall_Native_vvMdnsEvent<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    handle: jlong,
    json: JString<'l>,
) {
    guard(&mut env, (), |env| {
        let json = string(env, &json)?;
        if let Ok(event) = embed::event_from_json(&json) {
            engine(handle)?.networks().mdns_event(event);
        }
        Ok(())
    });
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_vardevall_Native_vvTunnelSettings<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    config: JString<'l>,
) -> jstring {
    guard(&mut env, std::ptr::null_mut(), |env| {
        let config = string(env, &config)?;
        let settings =
            embed::tunnel_settings(&config, &Context::default()).map_err(|e| e.to_string())?;
        output(env, &settings.to_json())
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_vardevall_Native_vvTunnelSettingsNetworks<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    names: JObjectArray<'l>,
    configs: JObjectArray<'l>,
) -> jstring {
    guard(&mut env, std::ptr::null_mut(), |env| {
        let specs = specs(env, &names, &configs)?;
        let settings = embed::tunnel_settings_networks(&specs).map_err(|e| e.to_string())?;
        output(env, &settings.to_json())
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_vardevall_Native_vvResolverAlias<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    ula: JString<'l>,
) -> jstring {
    guard(&mut env, std::ptr::null_mut(), |env| {
        let ula = string(env, &ula)?
            .parse()
            .map_err(|_| "not an IPv6 address".to_owned())?;
        output(env, &embed::resolver_alias(ula).to_string())
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_vardevall_Native_vvGenerateNodeKey<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
) -> jstring {
    guard(&mut env, std::ptr::null_mut(), |env| {
        output(env, &keys::generate_node_key())
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_vardevall_Native_vvGenerateNetworkSecret<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
) -> jstring {
    guard(&mut env, std::ptr::null_mut(), |env| {
        output(env, &keys::generate_network_secret())
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_vardevall_Native_vvPublicKey<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    secret: JString<'l>,
) -> jstring {
    guard(&mut env, std::ptr::null_mut(), |env| {
        let secret = string(env, &secret)?;
        let public = keys::public_key(&secret).map_err(|e| e.to_string())?;
        output(env, &public)
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_vardevall_Native_vvValidateConfig<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    config: JString<'l>,
) -> jstring {
    guard(&mut env, std::ptr::null_mut(), |env| {
        let config = string(env, &config)?;
        let parsed = Config::parse(&config, &Context::default()).map_err(|e| e.to_string())?;
        output(env, &parsed.summary().to_string())
    })
}
