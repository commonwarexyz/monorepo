use std::io::Result;
fn main() -> Result<()> {
    // Proto compilation rules for `linked` dialect
    let mut config = prost_build::Config::new();
    config.protoc_arg("--experimental_allow_proto3_optional");
    config.compile_protos(&["src/linked/wire.proto"], &["src/linked/"])?;

    // Proto compilation rules for `simplex` dialect
    let mut config = prost_build::Config::new();
    config.compile_protos(&["src/simplex/wire.proto"], &["src/simplex/"])?;

    // Proto compilation rules for `threshold_simplex` dialect
    let mut config = prost_build::Config::new();
    config.compile_protos(
        &["src/threshold_simplex/wire.proto"],
        &["src/threshold_simplex/"],
    )?;

    Ok(())
}
