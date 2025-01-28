use std::io::Result;
fn main() -> Result<()> {
    // Proto compilation rules for `linked` dialect
    let mut config = prost_build::Config::new();
    config.bytes([
        "Chunk.sequencer",
        "Chunk.payload_digest",
        "Chunk.signature",
        "Chunk.Parent.chunk_digest",
        "Chunk.Parent.threshold",
        "Ack.sequencer",
        "Ack.chunk_digest",
        "Ack.partial",
    ]);
    config.compile_protos(&["src/linked/wire.proto"], &["src/linked/"])?;
    Ok(())
}
