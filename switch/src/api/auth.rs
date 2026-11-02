//! Operator tokens (vv-04 §3.3).

use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use http::HeaderMap;
use vardevall_proto::keys::crypto;

use crate::config::{TokenSettings, TurnLimits};

const CONTEXT: &str = "vardevall switch token";

fn digest(token: &[u8]) -> [u8; 32] {
    crypto::kdf(CONTEXT, &[token])
}

type Digest = [u8; 32];

/// Most TURN limit classes a process hands out (the class is one byte of the credential id).
const MAX_CLASSES: usize = 250;

/// A reload could not be applied.
#[derive(Debug, thiserror::Error)]
pub enum ReloadError {
    /// The configuration or the token file could not be read or parsed.
    #[error(transparent)]
    Config(#[from] crate::config::ConfigError),
    /// The file names tokens but none were read, which would open registration.
    #[error("tokens are configured but none were read; refusing to open registration")]
    Emptied,
    /// Credentials already issued name more limit classes than a credential can carry.
    #[error("more than {MAX_CLASSES} different TURN limits since start; restart to reset them")]
    TooManyClasses,
}

/// One version of the accepted tokens.
struct TokenSet {
    digests: Vec<Digest>,
    /// Tokens whose TURN limits differ from the default, with their class.
    classed: Vec<(Digest, u8)>,
    /// The limits of classes 1.. . Classes are never reused or changed within a process, so a
    /// credential keeps its meaning across reloads.
    table: Vec<TurnLimits>,
}

impl TokenSet {
    /// The set of `settings` over the class `table` of the previous set.
    fn build(
        settings: &TokenSettings,
        base: TurnLimits,
        mut table: Vec<TurnLimits>,
    ) -> Result<TokenSet, ReloadError> {
        let mut classed = Vec::new();
        for t in &settings.token_turn {
            let limits = t.limits_over(base);
            let class = if limits == base {
                0
            } else {
                let at = match table.iter().position(|l| *l == limits) {
                    Some(at) => at,
                    None => {
                        table.push(limits);
                        table.len() - 1
                    }
                };
                u8::try_from(at + 1).map_err(|_| ReloadError::TooManyClasses)?
            };
            if table.len() > MAX_CLASSES {
                return Err(ReloadError::TooManyClasses);
            }
            if class != 0 {
                classed.push((digest(t.token.as_bytes()), class));
            }
        }
        Ok(TokenSet {
            digests: settings
                .tokens
                .iter()
                .map(|t| digest(t.as_bytes()))
                .collect(),
            classed,
            table,
        })
    }

    fn required(&self) -> bool {
        !self.digests.is_empty()
    }

    fn lists(&self, d: &Digest) -> bool {
        self.digests
            .iter()
            .fold(false, |ok, accepted| ok | crypto::ct_eq(accepted, d))
    }

    fn class(&self, d: &Digest) -> u8 {
        self.classed.iter().fold(0, |found, (accepted, class)| {
            if crypto::ct_eq(accepted, d) {
                *class
            } else {
                found
            }
        })
    }
}

/// The token a registration was admitted with and the TURN class it carries.
pub struct Admission {
    /// The class of the credentials issued to the session (0 is the default of `[turn]`).
    pub class: u8,
    /// The digest of the bearer token; `None` if registration was open.
    pub token: Option<Digest>,
}

/// The accepted operator tokens (vv-04 §3.3), held as digests and compared in constant time.
///
/// The set can be replaced while the switch runs ([`Tokens::reload`]); readers never block.
pub struct Tokens {
    set: ArcSwap<TokenSet>,
    /// The defaults of `[turn]`, which a reload does not change.
    base: TurnLimits,
    writer: Mutex<()>,
}

impl Tokens {
    /// The tokens of `settings`; none means open registration.
    pub fn new(settings: &TokenSettings, base: TurnLimits) -> Result<Tokens, ReloadError> {
        Ok(Tokens {
            set: ArcSwap::from_pointee(TokenSet::build(settings, base, Vec::new())?),
            base,
            writer: Mutex::new(()),
        })
    }

    /// Replaces the set; on an error the previous one stays. Returns the number of tokens
    /// accepted.
    pub fn reload(&self, settings: &TokenSettings) -> Result<usize, ReloadError> {
        let _one_at_a_time = self.writer.lock().unwrap_or_else(|e| e.into_inner());
        let old = self.set.load();
        if old.required() && settings.configured && settings.tokens.is_empty() {
            return Err(ReloadError::Emptied);
        }
        let new = TokenSet::build(settings, self.base, old.table.clone())?;
        let count = new.digests.len();
        self.set.store(Arc::new(new));
        Ok(count)
    }

    /// The limits of TURN class `class`; unknown classes get the defaults.
    pub fn limits(&self, class: u8) -> TurnLimits {
        usize::from(class)
            .checked_sub(1)
            .and_then(|i| self.set.load().table.get(i).copied())
            .unwrap_or(self.base)
    }

    /// Whether registration needs a token (vv-04 §3.4 `token_required`).
    pub fn required(&self) -> bool {
        self.set.load().required()
    }

    /// Admits a registration: always when no token is required, otherwise only with
    /// `Authorization: Bearer <token>` naming an accepted token.
    pub fn admit(&self, headers: &HeaderMap) -> Option<Admission> {
        let set = self.set.load();
        if !set.required() {
            return Some(Admission {
                class: 0,
                token: None,
            });
        }
        let d = digest(bearer(headers)?.as_bytes());
        set.lists(&d).then(|| Admission {
            class: set.class(&d),
            token: Some(d),
        })
    }

    /// The class for new TURN credentials of a session admitted with `token`; `None` if that
    /// token is no longer accepted while registration is closed.
    pub fn renew(&self, token: Option<Digest>) -> Option<u8> {
        let set = self.set.load();
        match token {
            Some(d) if set.lists(&d) || !set.required() => Some(set.class(&d)),
            None if !set.required() => Some(0),
            _ => None,
        }
    }
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            let (scheme, token) = v.split_once(' ')?;
            scheme
                .eq_ignore_ascii_case("bearer")
                .then_some(token.trim())
        })
}

#[cfg(test)]
mod tests {
    use http::HeaderValue;

    use super::*;
    use crate::config::TokenTurn;

    fn with(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_str(value).unwrap(),
        );
        h
    }

    fn tokens(accepted: &[&str]) -> Tokens {
        Tokens::new(&settings(accepted, &[]), BASE).unwrap()
    }

    const BASE: TurnLimits = TurnLimits {
        bits_per_second: Some(1000),
        bytes: None,
    };

    fn settings(accepted: &[&str], turn: &[(&str, Option<u64>)]) -> TokenSettings {
        TokenSettings {
            tokens: accepted.iter().map(|t| (*t).to_owned()).collect(),
            token_turn: turn
                .iter()
                .map(|(t, bytes)| TokenTurn {
                    token: (*t).to_owned(),
                    bits_per_second: None,
                    bytes: *bytes,
                })
                .collect(),
            configured: !accepted.is_empty(),
        }
    }

    fn admits(t: &Tokens, h: &HeaderMap) -> bool {
        t.admit(h).is_some()
    }

    #[test]
    fn open_when_empty() {
        let t = tokens(&[]);
        assert!(admits(&t, &HeaderMap::new()));
        assert!(!t.required());
    }

    #[test]
    fn tokens_with_their_own_turn_limits_have_a_class() {
        let t = Tokens::new(
            &settings(
                &["alpha", "beta", "gamma"],
                &[("gamma", Some(7)), ("beta", Some(9))],
            ),
            BASE,
        )
        .unwrap();
        let class = |h: &HeaderMap| t.admit(h).unwrap().class;
        assert_eq!(class(&with("Bearer gamma")), 1);
        assert_eq!(class(&with("Bearer beta")), 2);
        assert_eq!(class(&with("Bearer alpha")), 0);
        assert_eq!(t.limits(1).bytes, Some(7));
        assert_eq!(t.limits(2).bytes, Some(9));
        assert_eq!(t.limits(0), BASE);
        assert_eq!(t.limits(200), BASE);
    }

    #[test]
    fn requires_a_listed_bearer_token() {
        let t = tokens(&["alpha", "beta"]);
        assert!(t.required());
        assert!(admits(&t, &with("Bearer alpha")));
        assert!(admits(&t, &with("bearer beta")));
        assert!(!admits(&t, &with("Bearer gamma")));
        assert!(!admits(&t, &with("Basic alpha")));
        assert!(!admits(&t, &with("alpha")));
        assert!(!admits(&t, &HeaderMap::new()));
    }

    #[test]
    fn reload_swaps_the_list_and_keeps_classes_stable() {
        let t = Tokens::new(&settings(&["a", "b"], &[("a", Some(7))]), BASE).unwrap();
        let a = t.admit(&with("Bearer a")).unwrap();
        assert_eq!(a.class, 1);
        // `b` gets limits of its own and `a` changes: `a` moves to a new class, the old one
        // keeps its limits for credentials already issued.
        let n = t
            .reload(&settings(&["a", "c"], &[("c", Some(7)), ("a", Some(8))]))
            .unwrap();
        assert_eq!(n, 2);
        assert!(!admits(&t, &with("Bearer b")));
        assert_eq!(t.admit(&with("Bearer c")).unwrap().class, 1);
        assert_eq!(t.admit(&with("Bearer a")).unwrap().class, 2);
        assert_eq!(t.limits(1).bytes, Some(7));
        assert_eq!(t.limits(2).bytes, Some(8));
        assert_eq!(t.renew(a.token), Some(2));
    }

    #[test]
    fn a_removed_token_gets_no_more_credentials_while_closed() {
        let t = tokens(&["a", "b"]);
        let a = t.admit(&with("Bearer a")).unwrap().token;
        let open = t.admit(&with("Bearer b")).unwrap().token;
        t.reload(&settings(&["b"], &[])).unwrap();
        assert_eq!(t.renew(a), None);
        assert_eq!(t.renew(open), Some(0));
        assert_eq!(t.renew(None), None);
        let mut gone = settings(&[], &[]);
        gone.configured = false;
        t.reload(&gone).unwrap();
        assert!(!t.required());
        assert_eq!(t.renew(a), Some(0));
        assert_eq!(t.renew(None), Some(0));
    }

    #[test]
    fn a_configured_but_empty_list_does_not_open_registration() {
        let t = tokens(&["a"]);
        let mut empty = settings(&[], &[]);
        empty.configured = true;
        assert!(matches!(t.reload(&empty), Err(ReloadError::Emptied)));
        assert!(t.required());
    }

    #[test]
    fn the_class_table_is_bounded() {
        let t = tokens(&["a"]);
        for n in 0..MAX_CLASSES as u64 {
            t.reload(&settings(&["a"], &[("a", Some(n + 1))])).unwrap();
        }
        let r = t.reload(&settings(&["a"], &[("a", Some(10_000))]));
        assert!(matches!(r, Err(ReloadError::TooManyClasses)));
        assert!(t.admit(&with("Bearer a")).is_some());
    }
}
