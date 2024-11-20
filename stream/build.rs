use std::io::Result;
fn main() -> Result<()> {
    // Proto compilation rules for `connection` dialect
    let mut config = prost_build::Config::new();
    config.bytes([
        "Signature.public_key",
        "Signature.signature",
        "Handshake.recipient_public_key",
        "Handshake.ephemeral_public_key",
    ]);
    config.compile_protos(&["src/connection/wire.proto"], &["src/connection/"])?;
    Ok(())
}
