use std::io::Result;
fn main() -> Result<()> {
    // Proto compilation rules for `simplex` dialect
    let mut config = prost_build::Config::new();
    config.bytes([
        "Signature.public_key",
        "Signature.signature",
        "Parent.digest",
        "Proposal.payload",
    ]);
    config.compile_protos(&["src/simplex/wire.proto"], &["src/simplex/"])?;
    Ok(())
}
