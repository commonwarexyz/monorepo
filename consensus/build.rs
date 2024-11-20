use std::io::Result;
fn main() -> Result<()> {
    // Proto compilation rules for `fixed` dialect
    let mut config = prost_build::Config::new();
    config.bytes([
        "Signature.public_key",
        "Signature.signature",
        "Parent.digest",
        "Proposal.payload",
    ]);
    config.compile_protos(&["src/authority/wire.proto"], &["src/authority/"])?;
    Ok(())
}
