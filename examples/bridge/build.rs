use std::io::Result;
fn main() -> Result<()> {
    let mut config = prost_build::Config::new();
    config.protoc_arg("--experimental_allow_proto3_optional");
    config.bytes(["PutBlock.data", "GetBlock.digest", "PutFinalization.data"]);
    config.compile_protos(&["src/wire.proto"], &["src/"])?;
    Ok(())
}
