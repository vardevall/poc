//! A parser for the Server-Sent Events stream of a switch (vv-04 §7.1).

/// Most bytes buffered for one event; a forwarded datagram is under 8 kB.
const MAX_EVENT: usize = 32 * 1024;

/// One dispatched event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sse {
    /// The `event` field, empty if absent.
    pub name: String,
    /// The `data` lines joined with newlines.
    pub data: Vec<u8>,
}

/// The stream carried more than [`MAX_EVENT`] bytes without ending an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Overflow;

/// Accumulates bytes and yields complete events.
#[derive(Default)]
pub struct SseParser {
    buf: Vec<u8>,
    name: String,
    data: Vec<u8>,
    has_data: bool,
}

impl SseParser {
    /// An empty parser.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds received bytes.
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), Overflow> {
        if self.buf.len() + self.data.len() + bytes.len() > MAX_EVENT {
            return Err(Overflow);
        }
        self.buf.extend_from_slice(bytes);
        Ok(())
    }

    /// The next complete event, if the buffered bytes hold one.
    pub fn next_event(&mut self) -> Option<Sse> {
        loop {
            let end = self.buf.iter().position(|&b| b == b'\n')?;
            let mut line: Vec<u8> = self.buf.drain(..=end).collect();
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            if line.is_empty() {
                let event = Sse {
                    name: std::mem::take(&mut self.name),
                    data: std::mem::take(&mut self.data),
                };
                let dispatch = std::mem::take(&mut self.has_data);
                if dispatch {
                    return Some(event);
                }
                continue;
            }
            if line[0] == b':' {
                continue;
            }
            let (field, value) = match line.iter().position(|&b| b == b':') {
                Some(i) => {
                    let v = &line[i + 1..];
                    (&line[..i], v.strip_prefix(b" ").unwrap_or(v))
                }
                None => (&line[..], &b""[..]),
            };
            match field {
                b"event" => self.name = String::from_utf8_lossy(value).into_owned(),
                b"data" => {
                    if self.has_data {
                        self.data.push(b'\n');
                    }
                    self.data.extend_from_slice(value);
                    self.has_data = true;
                }
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all(p: &mut SseParser) -> Vec<Sse> {
        std::iter::from_fn(|| p.next_event()).collect()
    }

    #[test]
    fn events_comments_and_split_input() {
        let mut p = SseParser::new();
        let input = b": vv-switch\n\nid: 1\nevent: online\ndata: {\"a\":1}\n\n: keepalive\n\nid: 2\nevent: offline\r\ndata: {}\r\n\r\n";
        for chunk in input.chunks(5) {
            p.push(chunk).unwrap();
        }
        let events = all(&mut p);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].name, "online");
        assert_eq!(events[0].data, b"{\"a\":1}");
        assert_eq!(events[1].name, "offline");
        assert_eq!(events[1].data, b"{}");
    }

    #[test]
    fn multi_line_data_and_missing_name() {
        let mut p = SseParser::new();
        p.push(b"data: a\ndata: b\n\ndata\n\n").unwrap();
        let events = all(&mut p);
        assert_eq!(events[0].data, b"a\nb");
        assert_eq!(events[0].name, "");
        assert_eq!(events[1].data, b"");
    }

    #[test]
    fn partial_events_wait_and_oversize_input_is_refused() {
        let mut p = SseParser::new();
        p.push(b"event: x\ndata: 1").unwrap();
        assert!(p.next_event().is_none());
        p.push(b"\n\n").unwrap();
        assert_eq!(p.next_event().unwrap().data, b"1");
        assert_eq!(p.push(&vec![b'a'; MAX_EVENT + 1]), Err(Overflow));
    }

    #[test]
    fn garbage_does_not_panic() {
        let mut p = SseParser::new();
        for b in 0..=255u8 {
            let _ = p.push(&[b, b':', b, b'\n', b'\n']);
            let _ = all(&mut p);
        }
    }
}
