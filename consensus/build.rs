use std::io::Result;
fn main() -> Result<()> {
    // Proto compilation rules for `simplex` dialect
    let mut config = prost_build::Config::new();
    config.bytes([
        "Parent.digest",
        "Proposal.payload",
        "Part.partial_signature",
        "Seed.signature",
        "Notarize.partial_signature",
        "Notarization.signature",
        "Nullify.partial_signature",
        "Nullification.signature",
        "Finalize.partial_signature",
        "Finalization.signature",
    ]);
    config.compile_protos(&["src/simplex/wire.proto"], &["src/simplex/"])?;
    Ok(())
}
