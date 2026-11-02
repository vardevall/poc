//! The JSON of `vv_mdns_cb` requests and `vv_mdns_event` results (vv-09 §2, vardevall.h).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use vardevall::{Found, MdnsEvent, MdnsRequest};

/// A result that is not valid JSON of the documented shape.
#[derive(Debug, Error)]
#[error("invalid mDNS result: {0}")]
pub struct MdnsJsonError(#[from] serde_json::Error);

#[derive(Serialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum Request<'a> {
    Register {
        instance: &'a str,
        #[serde(rename = "type")]
        service_type: &'a str,
        port: u16,
        txt: BTreeMap<&'a str, &'a str>,
    },
    Unregister {
        instance: &'a str,
    },
    Browse,
    StopBrowse,
}

/// The JSON of a request.
pub fn request_to_json(request: &MdnsRequest) -> String {
    let json = match request {
        MdnsRequest::Register {
            instance,
            service_type,
            port,
            txt,
        } => Request::Register {
            instance,
            service_type,
            port: *port,
            txt: txt.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect(),
        },
        MdnsRequest::Unregister { instance } => Request::Unregister { instance },
        MdnsRequest::Browse => Request::Browse,
        MdnsRequest::StopBrowse => Request::StopBrowse,
    };
    serde_json::to_string(&json).unwrap_or_default()
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum Incoming {
    Found {
        instance: String,
        txt: BTreeMap<String, serde_json::Value>,
        port: u16,
        addrs: Vec<String>,
        ifindex: Option<u32>,
    },
    Lost {
        instance: String,
    },
}

/// Parses a browse result. Unknown members are ignored. Of `txt`, only the string values count;
/// of `addrs`, only the entries that parse, without their zone after `%`; `ifindex` defaults
/// to 0.
pub fn event_from_json(text: &str) -> Result<MdnsEvent, MdnsJsonError> {
    Ok(match serde_json::from_str(text)? {
        Incoming::Lost { instance } => MdnsEvent::Lost { instance },
        Incoming::Found {
            instance,
            txt,
            port,
            addrs,
            ifindex,
        } => MdnsEvent::Found(Found {
            instance,
            txt: txt
                .into_iter()
                .filter_map(|(k, v)| Some((k, v.as_str()?.to_owned())))
                .collect(),
            port,
            addrs: addrs
                .iter()
                .filter_map(|a| a.split('%').next()?.parse().ok())
                .collect(),
            ifindex: ifindex.unwrap_or(0),
        }),
    })
}
