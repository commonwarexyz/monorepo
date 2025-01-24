use std::io::Result;
fn main() -> Result<()> {
    // Proto compilation rules for `linked` dialect
    let mut config = prost_build::Config::new();
    config.bytes([
        "Chunk.sequencer",
        "Chunk.payload",
        "Chunk.parent_digest",
        "Chunk.parent_threshold",
        "Chunk.signature",
        "Ack.digest",
        "Ack.public_key",
        "Ack.signature",
    ]);
    config.compile_protos(&["src/linked/wire.proto"], &["src/linked/"])?;
    Ok(())
}
