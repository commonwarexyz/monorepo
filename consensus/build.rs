use std::io::Result;
fn main() -> Result<()> {
    // Proto compilation rules for `fixed` dialect
    let mut config = prost_build::Config::new();
    config.bytes([
        "Signature.public_key",
        "Signature.signature",
        "Proposal.payload",
        "Proposal.parent",
        "Vote.hash",
        "Notarization.hash",
        "Finalize.hash",
        "Finalization.hash",
        "Request.hash",
        "Missing.hash",
    ]);
    config.compile_protos(&["src/fixed/wire.proto"], &["src/fixed/"])?;
    Ok(())
}
