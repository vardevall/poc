//! TURN over a byte stream (RFC 8656 §4.1): STUN messages and ChannelData padded to four bytes.

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt};

/// Largest frame read from a stream.
pub const MAX_FRAME: usize = 16 * 1024;

/// Reads one frame: a STUN message or a ChannelData message with its padding removed. `None` at
/// the end of the stream.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Option<Vec<u8>>> {
    let mut head = [0u8; 4];
    match r.read_exact(&mut head).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = usize::from(u16::from_be_bytes([head[2], head[3]]));
    let (total, padded) = if head[0] <= 3 {
        (20 + len, 20 + len)
    } else {
        (4 + len, (4 + len).div_ceil(4) * 4)
    };
    if padded > MAX_FRAME || total < 4 || (head[0] <= 3 && total < 20) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame"));
    }
    let mut buf = vec![0u8; padded];
    buf[..4].copy_from_slice(&head);
    r.read_exact(&mut buf[4..]).await?;
    buf.truncate(total);
    Ok(Some(buf))
}

/// The bytes to write for one message: ChannelData is padded to four bytes.
pub fn frame(mut msg: Vec<u8>) -> Vec<u8> {
    if msg.first().is_some_and(|b| *b > 3) {
        msg.resize(msg.len().div_ceil(4) * 4, 0);
    }
    msg
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn frames_split_and_pad() {
        let mut stun = vec![0, 1, 0, 0, 0x21, 0x12, 0xa4, 0x42];
        stun.extend_from_slice(&[9; 12]);
        let channel = vec![0x40, 0, 0, 5, 1, 2, 3, 4, 5];
        let mut wire = frame(stun.clone());
        wire.extend(frame(channel.clone()));
        wire.extend(frame(stun.clone()));
        assert_eq!(wire.len(), 20 + 12 + 20);
        let mut r = &wire[..];
        assert_eq!(read_frame(&mut r).await.unwrap(), Some(stun.clone()));
        assert_eq!(read_frame(&mut r).await.unwrap(), Some(channel));
        assert_eq!(read_frame(&mut r).await.unwrap(), Some(stun));
        assert_eq!(read_frame(&mut r).await.unwrap(), None);
    }

    #[tokio::test]
    async fn oversize_and_truncated_frames_fail() {
        let mut r = &[0x40u8, 0, 0xff, 0xff][..];
        assert!(read_frame(&mut r).await.is_err());
        let mut r = &[0x40u8, 0, 0, 8, 1][..];
        assert!(read_frame(&mut r).await.is_err());
    }
}
