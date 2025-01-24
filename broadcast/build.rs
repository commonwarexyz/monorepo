use std::io::Result;
fn main() -> Result<()> {
    // Proto compilation rules for `linked` dialect
    let mut config = prost_build::Config::new();
    config.bytes([
        "Car.sequencer",
        "Car.payload",
        "Car.parent_digest",
        "Car.parent_threshold",
        "Car.signature",
        "Ack.digest",
        "Ack.signature",
    ]);
    config.compile_protos(&["src/linked/wire.proto"], &["src/linked/"])?;
    Ok(())
}
