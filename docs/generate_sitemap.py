#!/usr/bin/env python3

"""Generate a deterministic sitemap.xml for the static docs site."""

from __future__ import annotations

import subprocess
from pathlib import Path
from urllib.parse import urljoin
from xml.sax.saxutils import escape


DOCS_ROOT = Path(__file__).resolve().parent
BASE_URL = "https://commonware.xyz"
EXCLUDED_FILES = {"template.html"}
EXCLUDED_DIRS = {".venv"}
EXTRA_FILES = ["llms.txt", "robots.txt"]


def get_version() -> str:
    """Get latest git tag as version. Fails if no tag exists."""
    result = subprocess.run(
        ["git", "-C", str(DOCS_ROOT.parent), "describe", "--tags", "--abbrev=0"],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def get_commit() -> str:
    """Get short git commit hash."""
    try:
        result = subprocess.run(
            ["git", "-C", str(DOCS_ROOT.parent), "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        return "unknown"


def collect_html() -> list[Path]:
    """Return sorted relative paths of HTML files to include in the sitemap."""
    results = []
    for path in DOCS_ROOT.rglob("*.html"):
        rel = path.relative_to(DOCS_ROOT)

        if rel.name in EXCLUDED_FILES:
            continue
        if any(part.startswith(".") for part in rel.parts):
            continue
        if any(part in EXCLUDED_DIRS for part in rel.parts):
            continue
        if rel.parts[0] == "code":
            continue

        results.append(rel)

    return sorted(results)


CODE_EXTENSIONS = {".md", ".rs", ".toml"}


def collect_code(version_prefix: str) -> list[Path]:
    """Return sorted relative paths of code files from the versioned directory.

    Only collects from code/v<version>/ to avoid duplicating code/main/<commit>/
    in the sitemap. Both paths contain identical content.
    """
    code_dir = DOCS_ROOT / "code" / version_prefix
    if not code_dir.exists():
        return []

    results = []
    for path in code_dir.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix not in CODE_EXTENSIONS:
            continue

        rel = path.relative_to(DOCS_ROOT)
        if any(part.startswith(".") for part in rel.parts):
            continue

        results.append(rel)

    return sorted(results)


def build_url(rel: Path, base_url: str) -> str:
    """Convert a relative path to an absolute URL using the provided base."""
    normalized = base_url.rstrip("/") + "/"
    if rel == Path("index.html"):
        return normalized
    return urljoin(normalized, rel.as_posix())


def write_sitemap(urls: list[str]) -> None:
    """Write sitemap.xml with the provided URLs."""
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">',
    ]

    for url in urls:
        escaped_url = escape(url)
        lines.append("  <url>")
        lines.append(f"    <loc>{escaped_url}</loc>")
        lines.append("  </url>")

    lines.append("</urlset>")

    content = "\n".join(lines) + "\n"
    (DOCS_ROOT / "sitemap.xml").write_text(content, encoding="utf-8")


def write_llms_txt(version: str, commit: str) -> None:
    """Write llms.txt with versioned paths for LLM discovery."""
    content = f"""# Commonware Library

> Version: {version} (commit: {commit})

Find more information at [README.md](/code/{version}/README.md).

## Paths

- Versioned (stable): /code/{version}/
- Main branch (commit-specific): /code/main/{commit}/

View [sitemap.xml](/sitemap.xml) for all filepaths.
"""
    (DOCS_ROOT / "llms.txt").write_text(content, encoding="utf-8")


def main() -> None:
    version = get_version()
    commit = get_commit()

    # Write llms.txt with versioned paths
    write_llms_txt(version, commit)

    # Collect URLs - only use versioned path for code to avoid duplicates
    urls = [build_url(rel, BASE_URL) for rel in collect_html()]
    urls += [build_url(rel, BASE_URL) for rel in collect_code(f"v{version}")]
    for extra in EXTRA_FILES:
        urls.append(urljoin(BASE_URL.rstrip("/") + "/", extra))
    write_sitemap(urls)


if __name__ == "__main__":
    main()
