use std::io::Result;
fn main() -> Result<()> {
    // Proto compilation rules for `authenticated` dialect
    let mut config = prost_build::Config::new();
    config.bytes(["Data.message"]);
    config.compile_protos(&["src/authenticated/wire.proto"], &["src/authenticated/"])?;
    Ok(())
}
