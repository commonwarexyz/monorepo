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

    // Proto compilation rules for `threshold_simplex` dialect
    let mut config = prost_build::Config::new();
    config.bytes([
        "Parent.digest",
        "Proposal.payload",
        "Notarize.signature",
        "Notarize.seed",
        "Notarization.signature",
        "Notarization.seed",
        "Nullify.signature",
        "Nullify.seed",
        "Nullification.signature",
        "Nullification.seed",
        "Finalize.signature",
        "Finalization.signature",
        "Finalization.seed",
    ]);
    config.compile_protos(
        &["src/threshold_simplex/wire.proto"],
        &["src/threshold_simplex/"],
    )?;
    Ok(())
}
