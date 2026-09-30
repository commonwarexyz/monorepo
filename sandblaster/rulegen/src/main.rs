//! `sandblaster-rulegen [--check]`: regenerate the aegraph's rule library
//! (`sandblaster/front/lemmas/rules/*.core`) and the `cong_irr`
//! lemmas (`sandblaster/front/lemmas/cong.core`); `--check` only
//! compares them with the checked-in files (exit 1 when stale). Offline:
//! the build never runs it (see the library docs).

use std::process::ExitCode;

fn main() -> ExitCode {
    let check = std::env::args().any(|a| a == "--check");
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../front");
    let t = std::time::Instant::now();
    let r = sandblaster_front::elab::with_big_stack(|| {
        let mut env = sandblaster_rulegen::library_env()?;
        sandblaster_rulegen::generate(&mut env, &mut |m| eprintln!("rulegen: {m}"))
    });
    let files = match r {
        Ok(f) => f,
        Err(e) => {
            eprintln!("rulegen: {e}");
            return ExitCode::FAILURE;
        }
    };
    let mut stale = false;
    for (rel, text) in files {
        let path = root.join(&rel);
        let on_disk = std::fs::read_to_string(&path).unwrap_or_default();
        if on_disk == text {
            eprintln!("rulegen: {rel}: up to date ({} bytes)", text.len());
        } else if check {
            eprintln!("rulegen: {rel}: STALE");
            stale = true;
        } else {
            if let Some(d) = path.parent() {
                let _ = std::fs::create_dir_all(d);
            }
            std::fs::write(&path, &text).expect("write");
            eprintln!("rulegen: {rel}: written ({} bytes)", text.len());
        }
    }
    eprintln!("rulegen: done in {:?}", t.elapsed());
    if stale { ExitCode::FAILURE } else { ExitCode::SUCCESS }
}
