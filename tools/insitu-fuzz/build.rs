use quote::ToTokens;
use std::{collections::HashMap, fs, io::Write, path::Path};
use syn::{spanned::Spanned, visit::Visit}; // add this

fn main() {
    println!("cargo:rerun-if-changed=../..");

    // Skip if oracle already exists (avoids AFL builds breaking it)
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let oracle_path = Path::new(&manifest_dir).join("test_oracle.txt");
    if oracle_path.exists() {
        return;
    }

    let mut oracle: HashMap<String, Vec<(u32, u32)>> = HashMap::new();
    let repo_root = Path::new(&manifest_dir).join("../..");

    for entry in walkdir::WalkDir::new(&repo_root)
        .into_iter()
        .filter_entry(|e| !e.path().components().any(|c| c.as_os_str() == "target"))
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().map_or(false, |ext| ext == "rs"))
    {
        let path = entry.path();
        let Ok(content) = fs::read_to_string(path) else {
            continue;
        };
        let Ok(ast) = syn::parse_file(&content) else {
            continue;
        };

        let mut finder = TestFinder::default();
        finder.visit_file(&ast);

        if !finder.ranges.is_empty() {
            let key = path.canonicalize().unwrap().to_string_lossy().into_owned();
            oracle.insert(key, finder.ranges);
        }
    }

    // Sanity check: fail loudly if span locations aren't working (all 0:0)
    let has_zero_range = oracle
        .values()
        .any(|ranges| ranges.iter().any(|(s, e)| *s == 0 && *e == 0));
    if has_zero_range {
        panic!(
            "\n\n\
            ╔══════════════════════════════════════════════════════════════════╗\n\
            ║  ERROR: Oracle has 0:0 ranges - span locations not working!      ║\n\
            ║                                                                  ║\n\
            ║  This build cannot generate valid test oracle data.              ║\n\
            ║  Run 'cargo build' from insitu-fuzz root first, then rebuild.    ║\n\
            ╚══════════════════════════════════════════════════════════════════╝\n\n"
        );
    }

    // Write to project root so all builds (debug/release/AFL) use the same oracle
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let mut f = fs::File::create(Path::new(&manifest_dir).join("test_oracle.txt")).unwrap();
    for (path, ranges) in &oracle {
        for (start, end) in ranges {
            writeln!(f, "{}:{}:{}", path, start, end).unwrap();
        }
    }
}

#[derive(Default)]
struct TestFinder {
    ranges: Vec<(u32, u32)>,
}

impl<'ast> Visit<'ast> for TestFinder {
    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        let is_test = node.ident == "tests"
            || node.attrs.iter().any(|a| {
                a.path().is_ident("cfg") && a.meta.to_token_stream().to_string().contains("test")
            });

        if is_test {
            if let Some((_, items)) = &node.content {
                let start = node.mod_token.span().start().line as u32;
                let end = items
                    .last()
                    .map(|i| i.span().end().line as u32)
                    .unwrap_or(start);
                self.ranges.push((start, end));
            }
            return;
        }
        syn::visit::visit_item_mod(self, node);
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        if node.attrs.iter().any(|a| a.path().is_ident("test")) {
            let start = node.sig.fn_token.span().start().line as u32;
            let end = node.block.span().end().line as u32;
            self.ranges.push((start, end));
        }
        syn::visit::visit_item_fn(self, node);
    }
}
