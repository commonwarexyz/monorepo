//! Aptly-based apt package caching for S3
//!
//! This module provides functionality to cache apt packages (and their dependencies)
//! in S3, enabling faster and more reliable deployments by avoiding repeated downloads
//! from Ubuntu mirrors.
//!
//! # Architecture
//!
//! Packages are cached in S3 under:
//! ```text
//! tools/apt/{codename}/{arch}/{package}_{version}_{arch}.deb
//! ```
//!
//! During deployment:
//! 1. Required packages are downloaded from Ubuntu mirrors (if not already cached)
//! 2. Packages are uploaded to S3
//! 3. Instances download from S3 via pre-signed URLs
//! 4. Packages are installed using dpkg
//!
//! # Kernel-specific packages
//!
//! Packages like `linux-tools-$(uname -r)` are kernel-version specific and cannot
//! be pre-cached. These continue to use apt-get at install time.

use crate::aws::{
    s3::{cache_and_presign, object_exists, UploadSource, BUCKET_NAME, PRESIGN_DURATION, WGET},
    Architecture, Error,
};
use aws_sdk_s3::Client as S3Client;
use futures::future::try_join_all;
use std::{collections::HashMap, path::Path};
use tracing::{debug, info};

/// Prefix for apt package cache in S3
pub const APT_CACHE_PREFIX: &str = "tools/apt";

/// Ubuntu codename for the deployed instances
pub const UBUNTU_CODENAME: &str = "noble";

/// Base URL for Ubuntu package mirrors
const UBUNTU_MIRROR: &str = "http://archive.ubuntu.com/ubuntu";
const UBUNTU_PORTS_MIRROR: &str = "http://ports.ubuntu.com/ubuntu-ports";

/// Returns the S3 key for a cached apt package
pub fn apt_package_s3_key(codename: &str, arch: Architecture, filename: &str) -> String {
    format!(
        "{APT_CACHE_PREFIX}/{codename}/{arch}/{filename}",
        arch = arch.as_str()
    )
}

/// Returns the Ubuntu mirror URL for a package based on architecture
fn get_mirror_url(arch: Architecture) -> &'static str {
    match arch {
        Architecture::Arm64 => UBUNTU_PORTS_MIRROR,
        Architecture::X86_64 => UBUNTU_MIRROR,
    }
}

/// Returns the download URL for a package from Ubuntu mirrors
pub fn package_download_url(arch: Architecture, pool_path: &str) -> String {
    format!("{}/{}", get_mirror_url(arch), pool_path)
}

/// Pre-defined package pool paths for Ubuntu Noble (24.04)
/// These are the actual paths in the Ubuntu repository structure
pub fn get_package_pool_paths(arch: Architecture) -> HashMap<&'static str, &'static str> {
    let mut paths: HashMap<&'static str, &'static str> = HashMap::new();

    // Common packages across architectures (paths verified for Noble 24.04)
    match arch {
        Architecture::Arm64 => {
            paths.insert(
                "adduser",
                "pool/main/a/adduser/adduser_3.137ubuntu1_all.deb",
            );
            paths.insert(
                "libfontconfig1",
                "pool/main/f/fontconfig/libfontconfig1_2.15.0-1.1ubuntu2_arm64.deb",
            );
            paths.insert("tar", "pool/main/t/tar/tar_1.35+dfsg-3build1_arm64.deb");
            paths.insert("unzip", "pool/main/u/unzip/unzip_6.0-28ubuntu4.1_arm64.deb");
            paths.insert("wget", "pool/main/w/wget/wget_1.21.4-1ubuntu4.1_arm64.deb");
            paths.insert("jq", "pool/universe/j/jq/jq_1.7.1-3build1_arm64.deb");
            paths.insert(
                "libjemalloc2",
                "pool/universe/j/jemalloc/libjemalloc2_5.3.0-2build1_arm64.deb",
            );
            paths.insert(
                "logrotate",
                "pool/main/l/logrotate/logrotate_3.21.0-2build1_arm64.deb",
            );
            // Dependencies
            paths.insert("libacl1", "pool/main/a/acl/libacl1_2.3.2-1build1_arm64.deb");
            paths.insert(
                "libfreetype6",
                "pool/main/f/freetype/libfreetype6_2.13.2+dfsg-1build3_arm64.deb",
            );
            paths.insert(
                "libjq1",
                "pool/universe/j/jq/libjq1_1.7.1-3build1_arm64.deb",
            );
            paths.insert(
                "libonig5",
                "pool/universe/libo/libonig/libonig5_6.9.9-1build1_arm64.deb",
            );
            paths.insert(
                "libpng16-16t64",
                "pool/main/libp/libpng1.6/libpng16-16t64_1.6.43-5build1_arm64.deb",
            );
            paths.insert(
                "libbrotli1",
                "pool/main/b/brotli/libbrotli1_1.1.0-2build2_arm64.deb",
            );
            paths.insert(
                "libpsl5t64",
                "pool/main/libp/libpsl/libpsl5t64_0.21.2-1.1build1_arm64.deb",
            );
        }
        Architecture::X86_64 => {
            paths.insert(
                "adduser",
                "pool/main/a/adduser/adduser_3.137ubuntu1_all.deb",
            );
            paths.insert(
                "libfontconfig1",
                "pool/main/f/fontconfig/libfontconfig1_2.15.0-1.1ubuntu2_amd64.deb",
            );
            paths.insert("tar", "pool/main/t/tar/tar_1.35+dfsg-3build1_amd64.deb");
            paths.insert("unzip", "pool/main/u/unzip/unzip_6.0-28ubuntu4.1_amd64.deb");
            paths.insert("wget", "pool/main/w/wget/wget_1.21.4-1ubuntu4.1_amd64.deb");
            paths.insert("jq", "pool/universe/j/jq/jq_1.7.1-3build1_amd64.deb");
            paths.insert(
                "libjemalloc2",
                "pool/universe/j/jemalloc/libjemalloc2_5.3.0-2build1_amd64.deb",
            );
            paths.insert(
                "logrotate",
                "pool/main/l/logrotate/logrotate_3.21.0-2build1_amd64.deb",
            );
            // Dependencies
            paths.insert("libacl1", "pool/main/a/acl/libacl1_2.3.2-1build1_amd64.deb");
            paths.insert(
                "libfreetype6",
                "pool/main/f/freetype/libfreetype6_2.13.2+dfsg-1build3_amd64.deb",
            );
            paths.insert(
                "libjq1",
                "pool/universe/j/jq/libjq1_1.7.1-3build1_amd64.deb",
            );
            paths.insert(
                "libonig5",
                "pool/universe/libo/libonig/libonig5_6.9.9-1build1_amd64.deb",
            );
            paths.insert(
                "libpng16-16t64",
                "pool/main/libp/libpng1.6/libpng16-16t64_1.6.43-5build1_amd64.deb",
            );
            paths.insert(
                "libbrotli1",
                "pool/main/b/brotli/libbrotli1_1.1.0-2build2_amd64.deb",
            );
            paths.insert(
                "libpsl5t64",
                "pool/main/libp/libpsl/libpsl5t64_0.21.2-1.1build1_amd64.deb",
            );
        }
    }

    paths
}

/// Returns the list of packages (with dependencies) for monitoring instances
pub fn monitoring_packages_with_deps() -> Vec<&'static str> {
    vec![
        // Direct packages
        "adduser",
        "libfontconfig1",
        "tar",
        "unzip",
        "wget",
        // Dependencies for libfontconfig1
        "libfreetype6",
        "libpng16-16t64",
        "libbrotli1",
        // Dependencies for wget
        "libpsl5t64",
    ]
}

/// Returns the list of packages (with dependencies) for binary instances
pub fn binary_packages_with_deps() -> Vec<&'static str> {
    vec![
        // Direct packages
        "jq",
        "libjemalloc2",
        "logrotate",
        "unzip",
        "wget",
        // Dependencies for jq
        "libjq1",
        "libonig5",
        // Dependencies for logrotate
        "libacl1",
        // Dependencies for wget
        "libpsl5t64",
        "libbrotli1",
    ]
}

/// Caches apt packages for the specified architecture and returns pre-signed URLs
pub async fn cache_apt_packages(
    s3_client: &S3Client,
    tag_directory: &Path,
    arch: Architecture,
    packages: &[&str],
) -> Result<HashMap<String, String>, Error> {
    let pool_paths = get_package_pool_paths(arch);
    let mut urls: HashMap<String, String> = HashMap::new();

    let cache_futures: Vec<_> = packages
        .iter()
        .filter_map(|&pkg| {
            pool_paths.get(pkg).map(|pool_path| {
                let s3_client = s3_client.clone();
                let tag_directory = tag_directory.to_path_buf();
                let pkg_name = pkg.to_string();
                let filename = pool_path.rsplit('/').next().unwrap().to_string();
                let s3_key = apt_package_s3_key(UBUNTU_CODENAME, arch, &filename);
                let download_url = package_download_url(arch, pool_path);

                async move {
                    // Check if already cached
                    if object_exists(&s3_client, BUCKET_NAME, &s3_key).await? {
                        debug!(
                            key = s3_key.as_str(),
                            package = pkg_name.as_str(),
                            "apt package already cached"
                        );
                        let url = crate::aws::s3::presign_url(
                            &s3_client,
                            BUCKET_NAME,
                            &s3_key,
                            PRESIGN_DURATION,
                        )
                        .await?;
                        return Ok::<_, Error>((pkg_name, filename, url));
                    }

                    // Download from Ubuntu mirror
                    info!(
                        package = pkg_name.as_str(),
                        url = download_url.as_str(),
                        "downloading apt package"
                    );
                    let temp_path = tag_directory.join(&filename);
                    crate::aws::utils::download_file(&download_url, &temp_path).await?;

                    // Upload to S3 and get pre-signed URL
                    let url = cache_and_presign(
                        &s3_client,
                        BUCKET_NAME,
                        &s3_key,
                        UploadSource::File(&temp_path),
                        PRESIGN_DURATION,
                    )
                    .await?;

                    // Clean up temp file
                    std::fs::remove_file(&temp_path)?;

                    info!(
                        package = pkg_name.as_str(),
                        key = s3_key.as_str(),
                        "cached apt package"
                    );

                    Ok((pkg_name, filename, url))
                }
            })
        })
        .collect();

    for result in try_join_all(cache_futures).await? {
        let (pkg_name, _filename, url) = result;
        urls.insert(pkg_name, url);
    }

    Ok(urls)
}

/// Generates the shell command to download and install cached apt packages
pub fn install_cached_packages_cmd(urls: &HashMap<String, String>, packages: &[&str]) -> String {
    let mut cmd = String::new();

    // Create temp directory for downloads
    cmd.push_str("mkdir -p /tmp/apt-cache\n");

    // Download all packages concurrently
    for pkg in packages {
        if let Some(url) = urls.get(*pkg) {
            let filename = url
                .split('/')
                .last()
                .and_then(|s| s.split('?').next())
                .unwrap_or(*pkg);
            cmd.push_str(&format!("{WGET} -O /tmp/apt-cache/{filename} '{url}' &\n"));
        }
    }
    cmd.push_str("wait\n");

    // Verify downloads
    cmd.push_str("for f in /tmp/apt-cache/*.deb; do\n");
    cmd.push_str("    if [ ! -f \"$f\" ]; then\n");
    cmd.push_str("        echo \"ERROR: Failed to download $(basename $f)\" >&2\n");
    cmd.push_str("        exit 1\n");
    cmd.push_str("    fi\n");
    cmd.push_str("done\n");

    // Install all packages with dpkg
    cmd.push_str("sudo dpkg -i /tmp/apt-cache/*.deb 2>/dev/null || true\n");

    // Fix any missing dependencies (for packages not in cache)
    cmd.push_str("sudo apt-get install -f -y\n");

    // Cleanup
    cmd.push_str("rm -rf /tmp/apt-cache\n");

    cmd
}

/// Generates the shell command to install kernel-specific packages via apt-get
pub fn install_kernel_packages_cmd() -> &'static str {
    r#"
# Install kernel-specific packages (cannot be pre-cached)
sudo apt-get update -y
sudo apt-get install -y linux-tools-common linux-tools-generic linux-tools-$(uname -r) || true
"#
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apt_package_s3_key() {
        assert_eq!(
            apt_package_s3_key(
                "noble",
                Architecture::Arm64,
                "wget_1.21.4-1ubuntu4.1_arm64.deb"
            ),
            "tools/apt/noble/arm64/wget_1.21.4-1ubuntu4.1_arm64.deb"
        );
        assert_eq!(
            apt_package_s3_key(
                "noble",
                Architecture::X86_64,
                "wget_1.21.4-1ubuntu4.1_amd64.deb"
            ),
            "tools/apt/noble/amd64/wget_1.21.4-1ubuntu4.1_amd64.deb"
        );
    }

    #[test]
    fn test_package_pool_paths_arm64() {
        let paths = get_package_pool_paths(Architecture::Arm64);
        assert!(paths.contains_key("wget"));
        assert!(paths.contains_key("jq"));
        assert!(paths.contains_key("libjemalloc2"));
        // Verify arm64 paths
        assert!(paths.get("wget").unwrap().contains("arm64"));
    }

    #[test]
    fn test_package_pool_paths_x86_64() {
        let paths = get_package_pool_paths(Architecture::X86_64);
        assert!(paths.contains_key("wget"));
        assert!(paths.contains_key("jq"));
        assert!(paths.contains_key("libjemalloc2"));
        // Verify amd64 paths
        assert!(paths.get("wget").unwrap().contains("amd64"));
    }

    #[test]
    fn test_monitoring_packages_with_deps() {
        let packages = monitoring_packages_with_deps();
        // Check direct packages
        assert!(packages.contains(&"adduser"));
        assert!(packages.contains(&"wget"));
        assert!(packages.contains(&"unzip"));
        // Check dependencies
        assert!(packages.contains(&"libfreetype6"));
    }

    #[test]
    fn test_binary_packages_with_deps() {
        let packages = binary_packages_with_deps();
        // Check direct packages
        assert!(packages.contains(&"jq"));
        assert!(packages.contains(&"libjemalloc2"));
        assert!(packages.contains(&"logrotate"));
        // Check dependencies
        assert!(packages.contains(&"libjq1"));
        assert!(packages.contains(&"libonig5"));
    }

    #[test]
    fn test_install_cached_packages_cmd() {
        let mut urls = HashMap::new();
        urls.insert(
            "wget".to_string(),
            "https://bucket.s3.amazonaws.com/tools/apt/noble/arm64/wget_1.21.4_arm64.deb?sig=xxx"
                .to_string(),
        );
        urls.insert(
            "jq".to_string(),
            "https://bucket.s3.amazonaws.com/tools/apt/noble/arm64/jq_1.7.1_arm64.deb?sig=xxx"
                .to_string(),
        );

        let cmd = install_cached_packages_cmd(&urls, &["wget", "jq"]);

        assert!(cmd.contains("mkdir -p /tmp/apt-cache"));
        assert!(cmd.contains("wget_1.21.4_arm64.deb"));
        assert!(cmd.contains("jq_1.7.1_arm64.deb"));
        assert!(cmd.contains("dpkg -i"));
        assert!(cmd.contains("apt-get install -f"));
    }
}
