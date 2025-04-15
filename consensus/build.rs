use std::io::Result;
fn main() -> Result<()> {
    // Proto compilation rules for `simplex` dialect
    let mut config = prost_build::Config::new();
    config.compile_protos(&["src/simplex/wire.proto"], &["src/simplex/"])?;

    Ok(())
}
