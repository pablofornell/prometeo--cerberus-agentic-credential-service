//! The ssh-agent wire protocol (draft-miller-ssh-agent), only the part the bridge speaks.
//!
//! Every message is `uint32 length`, then `byte type`, then the contents. The bridge answers
//! `REQUEST_IDENTITIES` and `SIGN_REQUEST`. Every other type (add, remove, lock, unlock,
//! smartcard, extension, SSH1) gets `SSH_AGENT_FAILURE`: agents cannot change the key list.

use tokio::io::{AsyncRead, AsyncReadExt};

/// Largest message the bridge reads, in bytes (the OpenSSH agent limit). A longer length ends
/// the connection.
pub const MAX_FRAME_BYTES: usize = 256 * 1024;

/// `SSH_AGENT_FAILURE`.
pub const SSH_AGENT_FAILURE: u8 = 5;
/// `SSH_AGENTC_REQUEST_IDENTITIES`.
pub const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
/// `SSH_AGENT_IDENTITIES_ANSWER`.
pub const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
/// `SSH_AGENTC_SIGN_REQUEST`.
pub const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
/// `SSH_AGENT_SIGN_RESPONSE`.
pub const SSH_AGENT_SIGN_RESPONSE: u8 = 14;

/// One request from a client.
#[derive(Debug, PartialEq, Eq)]
pub enum Request<'a> {
    /// List the keys.
    Identities,
    /// Sign `data` with the key `key_blob`.
    Sign {
        /// Public key in SSH wire form.
        key_blob: &'a [u8],
        /// The data to sign.
        data: &'a [u8],
        /// Signature flags (RSA hash choice; ed25519 has none).
        flags: u32,
    },
    /// Any other message, or a malformed one. The value is the message type (0 when empty).
    Refused(u8),
}

fn take_u32(input: &mut &[u8]) -> Option<u32> {
    let (head, rest) = input.split_first_chunk::<4>()?;
    *input = rest;
    Some(u32::from_be_bytes(*head))
}

fn take_string<'a>(input: &mut &'a [u8]) -> Option<&'a [u8]> {
    let len = usize::try_from(take_u32(input)?).ok()?;
    if input.len() < len {
        return None;
    }
    let (value, rest) = input.split_at(len);
    *input = rest;
    Some(value)
}

fn parse_sign(mut body: &[u8]) -> Option<Request<'_>> {
    let key_blob = take_string(&mut body)?;
    let data = take_string(&mut body)?;
    let flags = take_u32(&mut body)?;
    body.is_empty().then_some(Request::Sign {
        key_blob,
        data,
        flags,
    })
}

/// Reads one message body (type byte and contents, without the length).
#[must_use]
pub fn parse_request(message: &[u8]) -> Request<'_> {
    let Some((kind, body)) = message.split_first() else {
        return Request::Refused(0);
    };
    match *kind {
        SSH_AGENTC_REQUEST_IDENTITIES if body.is_empty() => Request::Identities,
        SSH_AGENTC_SIGN_REQUEST => parse_sign(body).unwrap_or(Request::Refused(*kind)),
        other => Request::Refused(other),
    }
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_string(out: &mut Vec<u8>, value: &[u8]) -> Option<()> {
    put_u32(out, u32::try_from(value.len()).ok()?);
    out.extend_from_slice(value);
    Some(())
}

/// Puts the length in front of a message body. `None` when the body is too long for a frame.
fn framed(body: Vec<u8>) -> Option<Vec<u8>> {
    if body.len() > MAX_FRAME_BYTES {
        return None;
    }
    let mut out = Vec::with_capacity(body.len() + 4);
    put_u32(&mut out, u32::try_from(body.len()).ok()?);
    out.extend_from_slice(&body);
    Some(out)
}

/// The framed `SSH_AGENT_FAILURE` message.
#[must_use]
pub fn failure() -> Vec<u8> {
    vec![0, 0, 0, 1, SSH_AGENT_FAILURE]
}

/// The framed `SSH_AGENT_IDENTITIES_ANSWER` for `keys` (key blob, comment). A list too long for
/// one frame gives the failure message.
#[must_use]
pub fn identities_answer(keys: &[(&[u8], &str)]) -> Vec<u8> {
    let build = || {
        let mut body = vec![SSH_AGENT_IDENTITIES_ANSWER];
        put_u32(&mut body, u32::try_from(keys.len()).ok()?);
        for (blob, comment) in keys {
            put_string(&mut body, blob)?;
            put_string(&mut body, comment.as_bytes())?;
        }
        framed(body)
    };
    build().unwrap_or_else(failure)
}

/// The framed `SSH_AGENT_SIGN_RESPONSE` for an SSH signature blob.
#[must_use]
pub fn sign_response(signature: &[u8]) -> Vec<u8> {
    let build = || {
        let mut body = vec![SSH_AGENT_SIGN_RESPONSE];
        put_string(&mut body, signature)?;
        framed(body)
    };
    build().unwrap_or_else(failure)
}

/// Why a frame could not be read. The connection is closed after any of them.
#[derive(Debug)]
pub enum FrameError {
    /// The length is 0 or above [`MAX_FRAME_BYTES`].
    BadLength(usize),
    /// The stream failed or ended inside a frame.
    Io(std::io::Error),
}

/// Reads one frame. `Ok(None)` when the peer closed the stream between frames.
///
/// # Errors
/// [`FrameError`] for a bad length or a broken stream.
pub async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Option<Vec<u8>>, FrameError> {
    let mut head = [0_u8; 4];
    match reader.read_exact(&mut head).await {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(FrameError::Io(error)),
    }
    let len = usize::try_from(u32::from_be_bytes(head)).unwrap_or(usize::MAX);
    if len == 0 || len > MAX_FRAME_BYTES {
        return Err(FrameError::BadLength(len));
    }
    let mut body = vec![0_u8; len];
    reader.read_exact(&mut body).await.map_err(FrameError::Io)?;
    Ok(Some(body))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sign_body(blob: &[u8], data: &[u8], flags: u32, extra: &[u8]) -> Vec<u8> {
        let mut out = vec![SSH_AGENTC_SIGN_REQUEST];
        put_string(&mut out, blob).unwrap();
        put_string(&mut out, data).unwrap();
        put_u32(&mut out, flags);
        out.extend_from_slice(extra);
        out
    }

    #[test]
    fn requests_parse() {
        assert_eq!(parse_request(&[11]), Request::Identities);
        assert_eq!(parse_request(&[11, 0]), Request::Refused(11));
        assert_eq!(parse_request(&[]), Request::Refused(0));
        let body = sign_body(b"key", b"data", 4, b"");
        assert_eq!(
            parse_request(&body),
            Request::Sign {
                key_blob: b"key",
                data: b"data",
                flags: 4
            }
        );
        assert_eq!(
            parse_request(&sign_body(b"key", b"data", 4, b"x")),
            Request::Refused(13)
        );
        assert_eq!(parse_request(&body[..body.len() - 1]), Request::Refused(13));
        let mut short = vec![13];
        put_u32(&mut short, 1000);
        assert_eq!(parse_request(&short), Request::Refused(13));
        for kind in [1_u8, 17, 18, 19, 20, 21, 22, 23, 25, 26, 27, 255] {
            assert_eq!(parse_request(&[kind, 0, 0]), Request::Refused(kind));
        }
    }

    #[test]
    fn answers_are_framed() {
        assert_eq!(failure(), vec![0, 0, 0, 1, 5]);
        assert_eq!(identities_answer(&[]), vec![0, 0, 0, 5, 12, 0, 0, 0, 0]);
        let one = identities_answer(&[(b"kb", "c")]);
        assert_eq!(
            one,
            vec![
                0, 0, 0, 16, 12, 0, 0, 0, 1, 0, 0, 0, 2, b'k', b'b', 0, 0, 0, 1, b'c'
            ]
        );
        assert_eq!(sign_response(b"s"), vec![0, 0, 0, 6, 14, 0, 0, 0, 1, b's']);
        assert_eq!(sign_response(&vec![0; MAX_FRAME_BYTES]), failure());
    }

    #[tokio::test]
    async fn frames_have_limits() {
        let mut ok: &[u8] = &[0, 0, 0, 1, 11];
        assert_eq!(read_frame(&mut ok).await.unwrap(), Some(vec![11]));
        assert!(read_frame(&mut ok).await.unwrap().is_none());
        let mut zero: &[u8] = &[0, 0, 0, 0];
        assert!(matches!(
            read_frame(&mut zero).await,
            Err(FrameError::BadLength(0))
        ));
        let big = u32::try_from(MAX_FRAME_BYTES + 1).unwrap().to_be_bytes();
        let mut large: &[u8] = &big;
        assert!(matches!(
            read_frame(&mut large).await,
            Err(FrameError::BadLength(_))
        ));
        let mut cut: &[u8] = &[0, 0, 0, 9, 11];
        assert!(matches!(read_frame(&mut cut).await, Err(FrameError::Io(_))));
    }
}
