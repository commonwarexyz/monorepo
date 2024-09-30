use std::io::Result;
fn main() -> Result<()> {
    // Proto compilation rules for `tbd` dialect
    let mut config = prost_build::Config::new();
    config.bytes([
        "Signature.public_key",
        "Signature.signature",
        "Propose.payload",
        "Propose.parent",
        "Vote.block",
    ]);
    config.compile_protos(&["src/tbd/wire.proto"], &["src/tbd/"])?;

    // Proto compilation rules for `simplex` dialect
    let mut config = prost_build::Config::new();
    config.bytes([
        "Signature.public_key",
        "Signature.signature",
        "Proposal.payload",
        "Proposal.parent",
        "Vote.block",
        "Notarization.block",
        "Finalize.block",
    ]);
    config.compile_protos(&["src/simplex/wire.proto"], &["src/simplex/"])?;
    Ok(())
}
