//! `GET /v0/members` and `GET /v0/members/<key>` (vv-04 §5).

use http::StatusCode;
use tokio::time::Instant;
use vardevall_proto::keys::NodePublic;

use crate::api::{Api, ApiError, ApiRequest, ApiResponse};
use crate::registry::MemberInfo;

fn member_json(m: &MemberInfo) -> String {
    format!(
        "{{\"node\":\"{}\",\"online_since\":{},\"gen\":{}}}",
        m.node, m.online_since, m.generation
    )
}

fn after(query: Option<&str>) -> Result<Option<NodePublic>, ApiError> {
    let Some(q) = query else {
        return Ok(None);
    };
    let mut found = None;
    for pair in q.split('&').filter(|p| !p.is_empty()) {
        match pair.split_once('=') {
            Some(("after", v)) => {
                found = Some(v.parse::<NodePublic>().map_err(|_| ApiError::Malformed)?)
            }
            _ => return Err(ApiError::Malformed),
        }
    }
    Ok(found)
}

impl Api {
    pub(crate) fn members(&self, req: &ApiRequest, now: Instant) -> Result<ApiResponse, ApiError> {
        let session = self.session(req)?;
        let (net, _) = self.registry.lookup(&session)?;
        let cursor = after(req.uri.query())?;
        self.limiters.members(&net, now)?;
        let (page, truncated) = self.registry.members(&session, cursor.as_ref())?;
        let list: Vec<String> = page.iter().map(member_json).collect();
        Ok(ApiResponse::json(
            StatusCode::OK,
            format!(
                "{{\"members\":[{}],\"truncated\":{truncated}}}",
                list.join(",")
            ),
        ))
    }

    pub(crate) fn member(
        &self,
        req: &ApiRequest,
        node: &NodePublic,
        now: Instant,
    ) -> Result<ApiResponse, ApiError> {
        let session = self.session(req)?;
        let (net, _) = self.registry.lookup(&session)?;
        self.limiters.members(&net, now)?;
        match self.registry.member(&session, node)? {
            Some(m) => Ok(ApiResponse::json(StatusCode::OK, member_json(&m))),
            None => Err(ApiError::NotOnline),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_parsing() {
        let k = NodePublic::from_bytes([5; 32]);
        assert_eq!(after(None).unwrap(), None);
        assert_eq!(after(Some("")).unwrap(), None);
        assert_eq!(after(Some(&format!("after={k}"))).unwrap(), Some(k));
        assert!(after(Some("after=zz")).is_err());
        assert!(after(Some("other=1")).is_err());
    }
}
