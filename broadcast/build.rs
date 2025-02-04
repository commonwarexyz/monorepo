use std::io::Result;
fn main() -> Result<()> {
    // Proto compilation rules for `linked` dialect
    let mut config = prost_build::Config::new();
    config.bytes([
        "Chunk.sequencer",
        "Parent.threshold",
        "Link.signature",
        "Ack.partial",
    ]);
    config.compile_protos(&["src/linked/wire.proto"], &["src/linked/"])?;
    Ok(())
}
