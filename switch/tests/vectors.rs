//! The registration vectors of vv-04 (`04-switch-api.json`) against the API handler.

use bytes::Bytes;
use http::{HeaderMap, Method, StatusCode, Uri};
use serde_json::Value;
use vardevall_proto::keys::{SwitchSecret, base32};
use vardevall_switch::api::{Api, ApiBody, ApiRequest, ConnInfo};
use vardevall_switch::config::Config;

fn vectors() -> Value {
    serde_json::from_str(include_str!("vectors/04-switch-api.json")).unwrap()
}

fn hex(v: &Value) -> Vec<u8> {
    let s = v.as_str().unwrap();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn arr<const N: usize>(v: &Value) -> [u8; N] {
    hex(v).try_into().unwrap()
}

fn config(names: &[&str]) -> Config {
    let mut config = Config::new(vec![], "unused".into());
    config.names = names.iter().map(|n| (*n).to_owned()).collect();
    config
}

fn error_type(body: &[u8]) -> String {
    let reply: Value = serde_json::from_slice(body).unwrap();
    reply["type"].as_str().unwrap().to_owned()
}

fn post(path: &'static str, body: &str) -> ApiRequest {
    ApiRequest {
        method: Method::POST,
        uri: Uri::from_static(path),
        headers: HeaderMap::new(),
        body: Bytes::from(body.to_owned()),
    }
}

fn body_of(r: vardevall_switch::api::ApiResponse) -> (StatusCode, Vec<u8>) {
    match r.body {
        ApiBody::Bytes(b) => (r.status, b.to_vec()),
        _ => (r.status, Vec::new()),
    }
}

#[tokio::test]
async fn exporter_registration_vector() {
    let doc = vectors();
    let v = doc["registration"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["input"].get("exporter").is_some())
        .unwrap();
    let input = &v["input"];
    let secret = SwitchSecret::from_bytes(arr(&input["switch_seed"]));
    assert_eq!(secret.public().as_bytes().to_vec(), hex(&input["A"]));
    let api = Api::new(&config(&[input["host"].as_str().unwrap()]), secret).unwrap();
    let conn = ConnInfo {
        peer: "192.0.2.1".parse().unwrap(),
        exporter: Some(arr(&input["exporter"])),
    };
    let request = post(
        "/v0/register",
        v["output"]["request_body"].as_str().unwrap(),
    );
    let (status, body) = body_of(api.handle(&conn, request.clone()));
    assert_eq!(status, StatusCode::OK);
    let reply: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        reply["switch_proof"].as_str().unwrap(),
        v["output"]["switch_proof_base32"].as_str().unwrap()
    );
    assert_eq!(
        base32::decode(reply["session"].as_str().unwrap())
            .unwrap()
            .len(),
        32
    );

    let other = ConnInfo {
        exporter: Some([0xee; 32]),
        ..conn.clone()
    };
    let (status, _) = body_of(api.handle(&other, request));
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn challenge_registration_vector_is_long_expired() {
    let doc = vectors();
    let v = doc["registration"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["input"].get("challenge").is_some())
        .unwrap();
    let secret = SwitchSecret::from_bytes(arr(&v["input"]["switch_seed"]));
    let api = Api::new(&config(&[v["input"]["host"].as_str().unwrap()]), secret).unwrap();
    let conn = ConnInfo {
        peer: "192.0.2.1".parse().unwrap(),
        exporter: None,
    };
    let (status, body) = body_of(api.handle(
        &conn,
        post(
            "/v0/register",
            v["output"]["request_body"].as_str().unwrap(),
        ),
    ));
    assert_eq!(status, StatusCode::FORBIDDEN);
    let reply: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(reply["type"], "urn:vardevall:error:invalid-proof");
}

fn relay_vector() -> Value {
    vectors()["proof_relay"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["input"].get("host").is_some() && v["input"].get("challenge").is_some())
        .unwrap()
        .clone()
}

#[tokio::test]
async fn proofs_under_another_host_are_refused_whether_or_not_the_switch_serves_it() {
    let doc = vectors();
    let v = doc["registration"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["input"].get("exporter").is_some())
        .unwrap();
    let input = &v["input"];
    let conn = ConnInfo {
        peer: "192.0.2.1".parse().unwrap(),
        exporter: Some(arr(&input["exporter"])),
    };
    let host = input["host"].as_str().unwrap();
    let body = v["output"]["request_body"].as_str().unwrap();
    let relay = relay_vector()["input"]["host"].as_str().unwrap().to_owned();
    let relayed = body.replace(host, &relay);
    assert_ne!(body, relayed);
    for names in [vec![host], vec![host, relay.as_str()]] {
        let secret = SwitchSecret::from_bytes(arr(&input["switch_seed"]));
        let api = Api::new(&config(&names), secret).unwrap();
        let (status, reply) = body_of(api.handle(&conn, post("/v0/register", &relayed)));
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(error_type(&reply), "urn:vardevall:error:invalid-proof");
    }
}

#[tokio::test]
async fn the_proofs_of_the_other_host_vector_are_refused_by_a_switch_that_does_not_serve_it() {
    let doc = vectors();
    let v = doc["registration"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["input"].get("challenge").is_some())
        .unwrap();
    let relay = relay_vector();
    let host = v["input"]["host"].as_str().unwrap();
    let other = relay["input"]["host"].as_str().unwrap();
    let proof = |name| base32::encode(&hex(&relay["output"][name]));
    let original = v["output"]["request_body"].as_str().unwrap();
    let body: Value = serde_json::from_str(original).unwrap();
    let relayed = original
        .replace(host, other)
        .replace(body["node_proof"].as_str().unwrap(), &proof("node_proof"))
        .replace(body["net_proof"].as_str().unwrap(), &proof("net_proof"));
    assert_ne!(original, relayed);
    let secret = SwitchSecret::from_bytes(arr(&v["input"]["switch_seed"]));
    let api = Api::new(&config(&[host]), secret).unwrap();
    let conn = ConnInfo {
        peer: "192.0.2.1".parse().unwrap(),
        exporter: None,
    };
    let (status, reply) = body_of(api.handle(&conn, post("/v0/register", &relayed)));
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(error_type(&reply), "urn:vardevall:error:invalid-proof");
}
