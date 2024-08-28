use std::io::Result;
fn main() -> Result<()> {
    let mut config = prost_build::Config::new();
    config.protoc_arg("--experimental_allow_proto3_optional");
    config.bytes([
        "Complaint.signature",
        "Reveal.signature",
        "Share.signature",
        "Resolution.signature",
    ]);
    config.compile_protos(&["src/wire.proto"], &["src/"])?;
    Ok(())
}
