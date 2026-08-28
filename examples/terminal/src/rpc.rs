//! Native, one-request/one-response framing for the terminal roles.

use anyhow::{Context as _, bail};
use bytes::Bytes;
use commonware_codec::{
    BufsMut, Decode, Encode, EncodeSize, Error as CodecError, Read, ReadExt, Write,
};
use commonware_runtime::{Buf, BufMut, Listener, Network, Sink, Stream};
use commonware_stream::{
    encrypted::Error,
    utils::codec::{recv_frame, send_frame},
};

/// Maximum encoded payload accepted in one RPC frame.
pub(crate) const MAX_FRAME_SIZE: u32 = 4 * 1024 * 1024;

/// Maximum request body or response body/error accepted by the codec.
///
/// The frame limit also includes the method/tag and length prefix. The small
/// amount of reserved space keeps every value at this limit representable in a
/// frame while leaving the bound independent of the exact varint width.
pub(crate) const MAX_BODY_SIZE: usize = MAX_FRAME_SIZE as usize - 16;

/// Maximum bytes retained from a human-readable RPC error message.
pub(crate) const MAX_ERROR_BYTES: usize = 1_024;

/// Truncates a UTF-8 message to `maximum` bytes on a character boundary.
pub(crate) fn bounded_utf8(mut value: String, maximum: usize) -> Bytes {
    if value.len() > maximum {
        let mut end = maximum;
        while !value.is_char_boundary(end) {
            end -= 1;
        }
        value.truncate(end);
    }
    Bytes::from(value)
}

/// Builds a bounded error response from a human-readable message.
pub(crate) fn error_response(message: String) -> Response {
    Response::Error {
        error: bounded_utf8(message, MAX_ERROR_BYTES),
    }
}

/// A single request sent over a native clearing connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Request {
    pub(crate) method: u8,
    pub(crate) body: Bytes,
}

impl Write for Request {
    fn write(&self, buf: &mut impl BufMut) {
        self.method.write(buf);
        self.body.write(buf);
    }

    fn write_bufs(&self, buf: &mut impl BufsMut) {
        self.method.write_bufs(buf);
        self.body.write_bufs(buf);
    }
}

impl EncodeSize for Request {
    fn encode_size(&self) -> usize {
        self.method.encode_size() + self.body.encode_size()
    }

    fn encode_inline_size(&self) -> usize {
        self.method.encode_size() + self.body.encode_inline_size()
    }
}

impl Read for Request {
    /// Maximum encoded body length.
    type Cfg = usize;

    fn read_cfg(buf: &mut impl Buf, max_body_size: &Self::Cfg) -> Result<Self, CodecError> {
        let method = u8::read(buf)?;
        let body = Bytes::read_cfg(buf, &(0..=*max_body_size).into())?;
        Ok(Self { method, body })
    }
}

/// A response to the one request received on a native clearing connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Response {
    Success { body: Bytes },
    Error { error: Bytes },
}

impl Write for Response {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Success { body } => {
                0u8.write(buf);
                body.write(buf);
            }
            Self::Error { error } => {
                1u8.write(buf);
                error.write(buf);
            }
        }
    }

    fn write_bufs(&self, buf: &mut impl BufsMut) {
        match self {
            Self::Success { body } => {
                0u8.write_bufs(buf);
                body.write_bufs(buf);
            }
            Self::Error { error } => {
                1u8.write_bufs(buf);
                error.write_bufs(buf);
            }
        }
    }
}

impl EncodeSize for Response {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Success { body } => body.encode_size(),
            Self::Error { error } => error.encode_size(),
        }
    }

    fn encode_inline_size(&self) -> usize {
        1 + match self {
            Self::Success { body } => body.encode_inline_size(),
            Self::Error { error } => error.encode_inline_size(),
        }
    }
}

impl Read for Response {
    /// Maximum encoded response body or error length.
    type Cfg = usize;

    fn read_cfg(buf: &mut impl Buf, max_body_size: &Self::Cfg) -> Result<Self, CodecError> {
        let tag = u8::read(buf)?;
        match tag {
            0 => Ok(Self::Success {
                body: Bytes::read_cfg(buf, &(0..=*max_body_size).into())?,
            }),
            1 => Ok(Self::Error {
                error: Bytes::read_cfg(buf, &(0..=*max_body_size).into())?,
            }),
            other => Err(CodecError::InvalidEnum(other)),
        }
    }
}

/// Sends exactly one request frame. Any error means that the connection must
/// be discarded because a partial frame may already have been written.
pub(crate) async fn send_request<S: Sink>(sink: &mut S, request: &Request) -> Result<(), Error> {
    if request.body.len() > MAX_BODY_SIZE {
        return Err(Error::SendTooLarge(request.body.len()));
    }
    send_frame(sink, request.encode(), MAX_FRAME_SIZE).await
}

/// Receives and fully decodes exactly one request frame.
pub(crate) async fn recv_request<T: Stream>(stream: &mut T) -> Result<Request, Error> {
    let frame = recv_frame(stream, MAX_FRAME_SIZE).await?;
    Ok(Request::decode_cfg(frame, &MAX_BODY_SIZE)?)
}

/// Sends exactly one response frame. Any error means that the connection must
/// be discarded because a partial frame may already have been written.
pub(crate) async fn send_response<S: Sink>(sink: &mut S, response: &Response) -> Result<(), Error> {
    let body_size = match response {
        Response::Success { body } => body.len(),
        Response::Error { error } => error.len(),
    };
    if body_size > MAX_BODY_SIZE {
        return Err(Error::SendTooLarge(body_size));
    }
    send_frame(sink, response.encode(), MAX_FRAME_SIZE).await
}

/// Receives and fully decodes exactly one response frame.
pub(crate) async fn recv_response<T: Stream>(stream: &mut T) -> Result<Response, Error> {
    let frame = recv_frame(stream, MAX_FRAME_SIZE).await?;
    Ok(Response::decode_cfg(frame, &MAX_BODY_SIZE)?)
}

/// Executes one request on a fresh connection.
pub(crate) async fn call<E: Network>(
    network: &E,
    address: std::net::SocketAddr,
    request: &Request,
) -> anyhow::Result<Response> {
    let (mut sink, mut stream) = network.dial(address).await?;
    send_request(&mut sink, request).await?;
    recv_response(&mut stream).await.map_err(Into::into)
}

/// Executes one request against the named role and unwraps its response envelope.
pub(crate) async fn invoke<E: Network>(
    network: &E,
    address: std::net::SocketAddr,
    role: &'static str,
    method: u8,
    body: Bytes,
) -> anyhow::Result<Bytes> {
    let response = call(network, address, &Request { method, body })
        .await
        .with_context(|| format!("call {role}"))?;
    match response {
        Response::Success { body } => Ok(body),
        Response::Error { error } => {
            bail!(
                "{role} rejected request: {}",
                String::from_utf8_lossy(&error)
            )
        }
    }
}

/// Serves one bounded request at a time.
///
/// Sequential ownership keeps mutable role state single-threaded and establishes a hard
/// one-connection admission bound for this local terminal. Runtime read/write deadlines
/// bound a peer that stops mid-frame.
pub(crate) async fn serve<E, F>(
    network: &E,
    address: std::net::SocketAddr,
    mut handle: F,
) -> anyhow::Result<()>
where
    E: Network,
    F: FnMut(Request) -> Response,
{
    let mut listener = network.bind(address).await?;
    loop {
        let (_, mut sink, mut stream) = listener.accept().await?;
        let Ok(request) = recv_request(&mut stream).await else {
            continue;
        };
        let response = handle(request);
        let _ = send_response(&mut sink, &response).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
    use commonware_codec::varint::UInt;
    use commonware_runtime::{Runner, Sink as RuntimeSink, deterministic, mocks};

    #[test]
    fn round_trip() {
        let (mut request_sink, mut request_stream) = mocks::Channel::init();
        let (mut response_sink, mut response_stream) = mocks::Channel::init();
        deterministic::Runner::default().start(|_| async move {
            let request = Request {
                method: 7,
                body: Bytes::from_static(b"request"),
            };
            send_request(&mut request_sink, &request).await.unwrap();
            assert_eq!(recv_request(&mut request_stream).await.unwrap(), request);

            let response = Response::Success {
                body: Bytes::from_static(b"response"),
            };
            send_response(&mut response_sink, &response).await.unwrap();
            assert_eq!(recv_response(&mut response_stream).await.unwrap(), response);
        });
    }

    #[test]
    fn unknown_response_tag_is_rejected() {
        let (mut sink, mut stream) = mocks::Channel::init();
        deterministic::Runner::default().start(|_| async move {
            send_frame(&mut sink, Bytes::from_static(&[0xff]), MAX_FRAME_SIZE)
                .await
                .unwrap();
            let result = recv_response(&mut stream).await;
            assert!(matches!(
                result,
                Err(Error::UnableToDecode(CodecError::InvalidEnum(0xff)))
            ));
        });
    }

    #[test]
    fn oversized_inner_body_is_rejected() {
        let (mut sink, mut stream) = mocks::Channel::init();
        deterministic::Runner::default().start(|_| async move {
            let mut encoded = BytesMut::new();
            1u8.write(&mut encoded);
            (MAX_BODY_SIZE + 1).write(&mut encoded);
            send_frame(&mut sink, encoded.freeze(), MAX_FRAME_SIZE)
                .await
                .unwrap();

            let result = recv_request(&mut stream).await;
            assert!(matches!(
                result,
                Err(Error::UnableToDecode(CodecError::InvalidLength(length)))
                    if length == MAX_BODY_SIZE + 1
            ));
        });
    }

    #[test]
    fn oversized_outer_frame_is_rejected() {
        let (mut sink, mut stream) = mocks::Channel::init();
        deterministic::Runner::default().start(|_| async move {
            RuntimeSink::send(&mut sink, UInt(MAX_FRAME_SIZE + 1).encode())
                .await
                .unwrap();

            let result = recv_request(&mut stream).await;
            assert!(matches!(
                result,
                Err(Error::RecvTooLarge(length)) if length == MAX_FRAME_SIZE as usize + 1
            ));
        });
    }

    #[test]
    fn trailing_data_is_rejected() {
        let (mut sink, mut stream) = mocks::Channel::init();
        deterministic::Runner::default().start(|_| async move {
            let request = Request {
                method: 2,
                body: Bytes::from_static(b"body"),
            };
            let mut encoded = request.encode().to_vec();
            encoded.push(0xaa);
            send_frame(&mut sink, encoded, MAX_FRAME_SIZE)
                .await
                .unwrap();

            let result = recv_request(&mut stream).await;
            assert!(matches!(
                result,
                Err(Error::UnableToDecode(CodecError::ExtraData(1)))
            ));
        });
    }

    #[test]
    fn empty_request_is_rejected() {
        let (mut sink, mut stream) = mocks::Channel::init();
        deterministic::Runner::default().start(|_| async move {
            send_frame(&mut sink, Bytes::new(), MAX_FRAME_SIZE)
                .await
                .unwrap();
            let result = recv_request(&mut stream).await;
            assert!(matches!(
                result,
                Err(Error::UnableToDecode(CodecError::EndOfBuffer))
            ));
        });
    }

    #[test]
    fn errors_are_utf8_and_truncated_on_a_character_boundary() {
        let response = error_response("é".repeat(MAX_ERROR_BYTES));
        let Response::Error { error } = response else {
            unreachable!();
        };
        assert_eq!(error.len(), MAX_ERROR_BYTES);
        assert!(core::str::from_utf8(&error).is_ok());
    }
}
