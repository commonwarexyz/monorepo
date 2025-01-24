use std::io::Result;
fn main() -> Result<()> {
    // Proto compilation rules for `linked` dialect
    let mut config = prost_build::Config::new();
    config.bytes([
        "Chunk.sequencer",
        "Chunk.payload",
        "Chunk.signature",
        "Parent.digest",
        "Parent.threshold",
        "Ack.digest",
        "Ack.partial",
    ]);
    config.compile_protos(&["src/linked/wire.proto"], &["src/linked/"])?;
    Ok(())
}
