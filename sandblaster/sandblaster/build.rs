//! Computes the toolchain identity (`toolchain_id.rs`, DESIGN.md §2.1
//! *Re-runs*) and passes it to the facade as `SANDBLASTER_TOOLCHAIN_ID`
//! (empty when it cannot be computed: then no verdict is reused). Every
//! file it hashes is watched, so a toolchain edit recomputes it.

#[path = "toolchain_id.rs"]
mod toolchain_id;

use std::path::PathBuf;

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-changed=toolchain_id.rs");
    println!("cargo::rerun-if-env-changed=CARGO_ENCODED_RUSTFLAGS");
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default());
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
    let rustc_vv = std::process::Command::new(&rustc).arg("-vV").output().ok().filter(|o| o.status.success()).map(|o| String::from_utf8_lossy(&o.stdout).into_owned());
    let build = |vv: String| {
        vec![
            ("rustc", vv),
            ("host", std::env::var("TARGET").unwrap_or_default()),
            ("rustflags", std::env::var("CARGO_ENCODED_RUSTFLAGS").unwrap_or_default()),
        ]
    };
    let result = (|| -> Result<(String, Vec<PathBuf>), String> {
        let vv = rustc_vv.ok_or_else(|| format!("`{rustc} -vV` failed"))?;
        let lock = toolchain_id::find_lock(&manifest).ok_or("no Cargo.lock above the facade")?;
        let lock_text = std::fs::read_to_string(&lock).map_err(|e| format!("cannot read `{}`: {e}", lock.display()))?;
        let locals = toolchain_id::local_packages(manifest.parent().ok_or("the facade has no parent directory")?);
        let (id, _, mut watch) = toolchain_id::identity(&lock_text, "sandblaster", &locals, &build(vv))?;
        watch.push(lock);
        Ok((id, watch))
    })();
    match result {
        Ok((id, watch)) => {
            for w in watch {
                println!("cargo::rerun-if-changed={}", w.display());
            }
            println!("cargo::rustc-env=SANDBLASTER_TOOLCHAIN_ID={id}");
        }
        Err(e) => {
            println!("cargo::warning=sandblaster: no toolchain identity ({e}): verdicts will not be reused");
            println!("cargo::rustc-env=SANDBLASTER_TOOLCHAIN_ID=");
        }
    }
}
