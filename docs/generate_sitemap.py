#!/usr/bin/env python3

"""Generate a deterministic sitemap index for the static docs site.

Creates a sitemap index with separate sitemaps for pages (high priority for
search engines) and code files (lower priority, primarily for LLMs). This
split helps search engines prioritize crawling the main content pages.
"""

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


def get_versions() -> list[str]:
    """Get last 3 git tags as versions. Fails if no tag exists."""
    result = subprocess.run(
        ["git", "-C", str(DOCS_ROOT.parent), "tag", "-l", "v*", "--sort=-v:refname"],
        capture_output=True,
        text=True,
        check=True,
    )
    all_tags = [t for t in result.stdout.strip().split("\n") if t]
    if not all_tags:
        raise RuntimeError("No version tags found")
    return all_tags[:3]


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


def collect_code(version: str) -> list[Path]:
    """Return sorted relative paths of code files from the versioned directory."""
    code_dir = DOCS_ROOT / "code" / version
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


def write_sitemap_with_priority(
    filename: str, urls: list[str], priority: str = "0.5"
) -> None:
    """Write a sitemap file with priority tags."""
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">',
    ]

    for url in urls:
        escaped_url = escape(url)
        lines.append("  <url>")
        lines.append(f"    <loc>{escaped_url}</loc>")
        lines.append(f"    <priority>{priority}</priority>")
        lines.append("  </url>")

    lines.append("</urlset>")

    content = "\n".join(lines) + "\n"
    (DOCS_ROOT / filename).write_text(content, encoding="utf-8")


def write_sitemap_index(sitemaps: list[str]) -> None:
    """Write sitemap index that references individual sitemaps."""
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">',
    ]

    for sitemap in sitemaps:
        url = urljoin(BASE_URL.rstrip("/") + "/", sitemap)
        escaped_url = escape(url)
        lines.append("  <sitemap>")
        lines.append(f"    <loc>{escaped_url}</loc>")
        lines.append("  </sitemap>")

    lines.append("</sitemapindex>")

    content = "\n".join(lines) + "\n"
    (DOCS_ROOT / "sitemap.xml").write_text(content, encoding="utf-8")


def write_llms_txt(versions: list[str]) -> None:
    """Write llms.txt with versioned paths for LLM discovery."""
    latest = versions[0]
    version_lines = [f"- /code/{versions[0]}/ (latest)"]
    version_lines += [f"- /code/{v}/" for v in versions[1:]]
    content = f"""# Commonware Library

> Source code is mirrored at versioned paths under /code/. These paths are
> not browseable directories. Use [sitemap.xml](/sitemap.xml) to discover
> all available files (.rs, .md, .toml). If a file is not in the sitemap,
> it does not exist.

Start with [README.md](/code/{latest}/README.md) for an overview.

## Versions

{chr(10).join(version_lines)}
"""
    (DOCS_ROOT / "llms.txt").write_text(content, encoding="utf-8")


def main() -> None:
    versions = get_versions()

    # Write llms.txt with versioned paths
    write_llms_txt(versions)

    # Collect page URLs (high priority for search engines)
    page_urls = [build_url(rel, BASE_URL) for rel in collect_html()]
    for extra in EXTRA_FILES:
        page_urls.append(urljoin(BASE_URL.rstrip("/") + "/", extra))

    # Collect code URLs (lower priority, primarily for LLMs)
    code_urls = []
    for version in versions:
        code_urls += [build_url(rel, BASE_URL) for rel in collect_code(version)]

    # Write separate sitemaps with appropriate priorities
    # Pages get high priority (1.0) to signal importance to search engines
    write_sitemap_with_priority("sitemap-pages.xml", page_urls, priority="1.0")
    # Code files get low priority (0.1) - still discoverable but deprioritized
    write_sitemap_with_priority("sitemap-code.xml", code_urls, priority="0.1")

    # Write sitemap index referencing both (pages listed first for priority)
    write_sitemap_index(["sitemap-pages.xml", "sitemap-code.xml"])


if __name__ == "__main__":
    main()
