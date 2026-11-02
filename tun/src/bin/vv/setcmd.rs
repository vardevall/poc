//! The words of `vv set`:
//! `peer <key> [name <label>|none] [endpoint <host:port>|none] [remove]`, once or more.

use anyhow::{Result, bail};
use serde_json::{Map, Value, json};
use vardevall_proto::keys::NodePublic;

/// The `peers` of the control socket's `set` request for `words`.
pub fn parse(words: &[String]) -> Result<Vec<Value>> {
    let mut out: Vec<Map<String, Value>> = Vec::new();
    let mut it = words.iter().map(String::as_str);
    while let Some(word) = it.next() {
        match word {
            "peer" => {
                let Some(key) = it.next() else {
                    bail!("peer needs a key");
                };
                if key.parse::<NodePublic>().is_err() {
                    bail!("{key:?} is not a node public key");
                }
                out.push(Map::from_iter([("key".to_owned(), json!(key))]));
            }
            "name" | "endpoint" => {
                let Some(peer) = out.last_mut() else {
                    bail!("{word} comes after `peer <key>`");
                };
                let Some(value) = it.next() else {
                    bail!("{word} needs a value or `none`");
                };
                let value = if value == "none" {
                    Value::Null
                } else {
                    json!(value)
                };
                if peer.insert(word.to_owned(), value).is_some() {
                    bail!("{word} given twice for one peer");
                }
            }
            "remove" => {
                let Some(peer) = out.last_mut() else {
                    bail!("remove comes after `peer <key>`");
                };
                peer.insert("remove".to_owned(), json!(true));
            }
            other => bail!("unknown word {other:?}: expected peer, name, endpoint or remove"),
        }
    }
    if out.is_empty() {
        bail!("nothing to set: expected `peer <key> …`");
    }
    for peer in &out {
        if peer.contains_key("remove")
            && (peer.contains_key("name") || peer.contains_key("endpoint"))
        {
            bail!("remove takes no name or endpoint");
        }
    }
    Ok(out.into_iter().map(Value::Object).collect())
}

#[cfg(test)]
mod tests {
    use vardevall_tun::keys;

    use super::*;

    fn words(text: &str) -> Vec<String> {
        text.split_whitespace().map(str::to_owned).collect()
    }

    fn key() -> String {
        keys::public_key(&keys::generate_node_key()).unwrap()
    }

    #[test]
    fn a_peer_gets_a_name_an_endpoint_or_goes() {
        let (a, b) = (key(), key());
        let got = parse(&words(&format!(
            "peer {a} name lab endpoint 192.0.2.1:4455 peer {b} remove"
        )))
        .unwrap();
        assert_eq!(
            got,
            vec![
                json!({"key": a, "name": "lab", "endpoint": "192.0.2.1:4455"}),
                json!({"key": b, "remove": true}),
            ]
        );
        let cleared = parse(&words(&format!("peer {a} name none endpoint none"))).unwrap();
        assert_eq!(
            cleared,
            vec![json!({"key": a, "name": null, "endpoint": null})]
        );
    }

    #[test]
    fn what_does_not_fit_the_grammar_is_refused() {
        let a = key();
        for bad in [
            String::new(),
            "name lab".to_owned(),
            "peer".to_owned(),
            "peer notakey".to_owned(),
            format!("peer {a} name"),
            format!("peer {a} name x name y"),
            format!("peer {a} remove name x"),
            format!("peer {a} flavour sweet"),
            format!("remove peer {a}"),
        ] {
            assert!(parse(&words(&bad)).is_err(), "{bad:?}");
        }
    }
}
