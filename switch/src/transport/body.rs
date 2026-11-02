//! Writing [`ApiBody`] as an HTTP body.

use std::convert::Infallible;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};

use crate::api::ApiBody;
use crate::registry::EventStream;

/// The body of a response.
pub enum ResponseBody {
    /// No body.
    Empty,
    /// A complete body, taken on the first poll.
    Full(Option<Bytes>),
    /// An events stream.
    Events(Box<EventStream>),
}

impl From<ApiBody> for ResponseBody {
    fn from(b: ApiBody) -> Self {
        match b {
            ApiBody::Empty => ResponseBody::Empty,
            ApiBody::Bytes(b) => ResponseBody::Full(Some(b)),
            ApiBody::Events(s) => ResponseBody::Events(Box::new(s)),
        }
    }
}

impl Body for ResponseBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        match &mut *self {
            ResponseBody::Empty => Poll::Ready(None),
            ResponseBody::Full(b) => Poll::Ready(b.take().map(|b| Ok(Frame::data(b)))),
            ResponseBody::Events(s) => s.poll_next(cx).map(|c| c.map(|b| Ok(Frame::data(b)))),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            ResponseBody::Empty => true,
            ResponseBody::Full(b) => b.is_none(),
            ResponseBody::Events(_) => false,
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            ResponseBody::Empty => SizeHint::with_exact(0),
            ResponseBody::Full(b) => SizeHint::with_exact(b.as_ref().map_or(0, |b| b.len() as u64)),
            ResponseBody::Events(_) => SizeHint::default(),
        }
    }
}
