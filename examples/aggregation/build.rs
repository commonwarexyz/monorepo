use std::io::Result;
fn main() -> Result<()> {
    let mut config = prost_build::Config::new();
    config.bytes([
        "Signature.public_key",
        "Signature.signature",
        "Success.signature",
    ]);
    config.compile_protos(&["src/wire.proto"], &["src/"])?;
    Ok(())
}
