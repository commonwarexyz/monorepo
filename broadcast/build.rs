use std::io::Result;
fn main() -> Result<()> {
    // Proto compilation rules for `linked` dialect
    let mut config = prost_build::Config::new();
    config.bytes([
        "Car.sequencer",
        "Car.payload",
        "Car.parent_plate",
        "Car.parent_threshold",
        "Car.signature",
        "Ack.plate",
        "Ack.public_key",
        "Ack.signature",
        "Proof.threshold",
        "Backfill.public_key",
    ]);
    config.compile_protos(&["src/linked/wire.proto"], &["src/linked/"])?;
    Ok(())
}
