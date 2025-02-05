use std::io::Result;
fn main() -> Result<()> {
    // Proto compilation rules for `simplex` dialect
    let mut config = prost_build::Config::new();
    config.compile_protos(&["src/simplex/wire.proto"], &["src/simplex/"])?;

    // Proto compilation rules for `threshold_simplex` dialect
    let mut config = prost_build::Config::new();
    config.bytes([
        "Notarize.proposal_signature",
        "Notarize.seed_signature",
        "Notarization.proposal_signature",
        "Notarization.seed_signature",
        "Nullify.view_signature",
        "Nullify.seed_signature",
        "Nullification.view_signature",
        "Nullification.seed_signature",
        "Finalize.proposal_signature",
        "Finalization.proposal_signature",
        "Finalization.seed_signature",
    ]);
    config.compile_protos(
        &["src/threshold_simplex/wire.proto"],
        &["src/threshold_simplex/"],
    )?;
    Ok(())
}
