use std::{
    env, fs, io,
    path::{Component, Path, PathBuf},
};

fn main() {
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let dist = manifest_dir.join("../browser/dist");
    let output = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("embedded_assets.rs");

    println!("cargo:rerun-if-changed={}", dist.display());

    let mut files = Vec::new();
    if dist.is_dir() {
        collect_files(&dist, &dist, &mut files).unwrap();
    }
    files.sort_by(|left, right| left.0.cmp(&right.0));

    let mut generated = String::from("const GENERATED_ASSETS: &[(&str, &[u8])] = &[\n");
    for (asset_path, file_path) in files {
        generated.push_str(&format!(
            "    ({asset_path:?}, include_bytes!({file_path:?})),\n",
            file_path = file_path.to_string_lossy(),
        ));
    }
    generated.push_str("];\n");

    fs::write(output, generated).unwrap();
}

fn collect_files(
    root: &Path,
    directory: &Path,
    files: &mut Vec<(String, PathBuf)>,
) -> io::Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let path = entry.path();

        if file_type.is_dir() {
            collect_files(root, &path, files)?;
            continue;
        }
        if !file_type.is_file() {
            continue;
        }

        let relative = path
            .strip_prefix(root)
            .expect("walked path must remain below root");
        let mut asset_path = String::new();
        for component in relative.components() {
            let Component::Normal(component) = component else {
                continue;
            };
            asset_path.push('/');
            asset_path.push_str(&component.to_string_lossy());
        }
        files.push((asset_path, path));
    }
    Ok(())
}
