use std::io::Result;
fn main() -> Result<()> {
    // Proto compilation rules for `public_key` dialect
    let mut config = prost_build::Config::new();
    config.compile_protos(&["src/public_key/wire.proto"], &["src/public_key/"])?;
    Ok(())
}
