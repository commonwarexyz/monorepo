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
        "ConflictingProposal.header_hash_1",
        "ConflictingProposal.payload_hash_1",
        "ConflictingProposal.header_hash_2",
        "ConflictingProposal.payload_hash_2",
        "ConflictingVote.hash_1",
        "ConflictingVote.hash_2",
        "ConflictingFinalize.hash_1",
        "ConflictingFinalize.hash_2",
        "NullFinalize.hash",
    ]);
    config.compile_protos(&["src/authority/wire.proto"], &["src/authority/"])?;
    Ok(())
}
