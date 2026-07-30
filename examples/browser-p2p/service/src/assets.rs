//! Compile-time embedding for the Bun production bundle.
//!
//! Run `bun run build` in `../browser` before compiling this crate to embed its `dist/`
//! contents. The build remains valid when `dist/` is absent, which keeps clean source builds
//! independent of generated frontend files. Rebuild this crate after regenerating the bundle.

include!(concat!(env!("OUT_DIR"), "/embedded_assets.rs"));

/// An embedded response body and its HTTP metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Asset {
    /// URL path of the embedded file.
    pub path: &'static str,
    /// Complete response body.
    pub body: &'static [u8],
    /// Value for the HTTP `Content-Type` header.
    pub content_type: &'static str,
    /// Value for the HTTP `Cache-Control` header.
    pub cache_control: &'static str,
}

/// Read-only access to the frontend bundle embedded at compile time.
#[derive(Clone, Copy, Debug, Default)]
pub struct EmbeddedAssets;

impl EmbeddedAssets {
    /// Resolve an asset path, serving `index.html` for `/`.
    ///
    /// Query strings and fragments are ignored. Traversal-like and non-canonical paths are
    /// rejected rather than normalized.
    pub fn get(request_path: &str) -> Option<Asset> {
        let path = request_path.split(['?', '#']).next()?;
        let path = if path == "/" { "/index.html" } else { path };
        if !is_safe_path(path) {
            return None;
        }

        GENERATED_ASSETS
            .iter()
            .find(|(candidate, _)| *candidate == path)
            .map(|(path, body)| Asset {
                path,
                body,
                content_type: content_type(path),
                cache_control: cache_control(path),
            })
    }

    /// Report whether this binary contains a generated Bun bundle.
    pub const fn is_embedded() -> bool {
        !GENERATED_ASSETS.is_empty()
    }
}

fn is_safe_path(path: &str) -> bool {
    path.starts_with('/')
        && !path.contains('\0')
        && !path.contains('\\')
        && path
            .split('/')
            .all(|component| component != ".." && component != ".")
}

fn content_type(path: &str) -> &'static str {
    match path.rsplit_once('.').map(|(_, extension)| extension) {
        Some("css") => "text/css; charset=utf-8",
        Some("html") => "text/html; charset=utf-8",
        Some("ico") => "image/x-icon",
        Some("js") => "text/javascript; charset=utf-8",
        Some("json") => "application/json",
        Some("png") => "image/png",
        Some("svg") => "image/svg+xml",
        Some("wasm") => "application/wasm",
        Some("webp") => "image/webp",
        _ => "application/octet-stream",
    }
}

fn cache_control(path: &str) -> &'static str {
    if path == "/index.html" {
        return "no-cache";
    }
    "public, max-age=31536000, immutable"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_canonical_paths() {
        assert!(EmbeddedAssets::get("../index.html").is_none());
        assert!(EmbeddedAssets::get("/../index.html").is_none());
        assert!(EmbeddedAssets::get("/assets\\index.js").is_none());
    }

    #[test]
    fn recognizes_http_metadata() {
        assert_eq!(content_type("/app.js"), "text/javascript; charset=utf-8");
        assert_eq!(content_type("/module.wasm"), "application/wasm");
        assert_eq!(cache_control("/index.html"), "no-cache");
    }
}
