use bytes::{Buf, BufMut};
use commonware_cryptography::Sha256 as Digest;
use prost::DecodeError;

pub fn encode<B>(value: &Digest, buf: &mut B)
where
    B: BufMut,
{
    buf.put(value[..]);
}

pub fn decode<B>(buf: &mut B) -> Result<Digest, DecodeError>
where
    B: Buf,
{
    // Check if there are enough bytes in the buffer to read a digest.
    let digest_len = size_of::<Digest>();
    if buf.remaining() < digest_len {
        return Err(DecodeError::new("insufficient buffer length"));
    }

    // If there are enough contiguous bytes in the buffer, use them directly.
    let chunk = buf.chunk();
    if chunk.len() >= digest_len {
        let digest = Digest::try_from(&chunk[..digest_len])
            .map_err(|_| DecodeError::new("invalid digest length"))?;
        buf.advance(digest_len);
        return Ok(digest);
    }

    // Otherwise, copy the bytes into a temporary buffer.
    let mut temp = vec![0u8; digest_len];
    buf.copy_to_slice(&mut temp);
    let digest = Digest::try_from(buf).map_err(|_| DecodeError::new("invalid digest length"))?;
    Ok(digest)
}

pub fn encoded_len(value: &Digest) -> usize {
    size_of::<Digest>()
}
