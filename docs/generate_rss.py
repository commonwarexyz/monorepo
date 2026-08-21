#!/usr/bin/env python3

"""Generate an RSS 2.0 feed for Commonware blog posts."""

from __future__ import annotations

from datetime import datetime, timezone
from email.utils import format_datetime
from pathlib import Path
from xml.sax.saxutils import escape


DOCS_ROOT = Path(__file__).resolve().parent
BLOGS_ROOT = DOCS_ROOT / "blogs"
OUTPUT = DOCS_ROOT / "rss.xml"
CHANNEL_TITLE = "Commonware Blog"
CHANNEL_LINK = "https://commonware.xyz/blogs"
CHANNEL_DESCRIPTION = "Updates from Commonware."


def parse_frontmatter(path: Path) -> dict[str, str]:
    """Parse the simple key/value frontmatter used by blog markdown files."""
    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines or lines[0].strip() != "---":
        return {}

    metadata: dict[str, str] = {}
    for line in lines[1:]:
        if line.strip() == "---":
            break
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        metadata[key.strip()] = value
    return metadata


def parse_published_time(value: str) -> datetime:
    """Parse the ISO-8601 published-time frontmatter value."""
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def collect_posts() -> list[tuple[datetime, dict[str, str]]]:
    """Collect posts with the metadata required by RSS and sort newest first."""
    posts: list[tuple[datetime, dict[str, str]]] = []
    required = {"title", "description", "published-time", "url"}

    for path in BLOGS_ROOT.glob("*.md"):
        metadata = parse_frontmatter(path)
        if not required.issubset(metadata):
            continue
        posts.append((parse_published_time(metadata["published-time"]), metadata))

    posts.sort(key=lambda item: item[0], reverse=True)
    return posts


def write_rss(posts: list[tuple[datetime, dict[str, str]]]) -> None:
    """Write a deterministic RSS 2.0 document."""
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<rss version="2.0">',
        "  <channel>",
        f"    <title>{escape(CHANNEL_TITLE)}</title>",
        f"    <link>{escape(CHANNEL_LINK)}</link>",
        f"    <description>{escape(CHANNEL_DESCRIPTION)}</description>",
        "    <language>en-us</language>",
    ]

    if posts:
        lines.append(f"    <lastBuildDate>{format_datetime(posts[0][0])}</lastBuildDate>")

    for published, metadata in posts:
        title = escape(metadata["title"])
        description = escape(metadata["description"])
        url = escape(metadata["url"])
        lines.extend(
            [
                "    <item>",
                f"      <title>{title}</title>",
                f"      <link>{url}</link>",
                f"      <guid isPermaLink=\"true\">{url}</guid>",
                f"      <pubDate>{format_datetime(published)}</pubDate>",
                f"      <description>{description}</description>",
                "    </item>",
            ]
        )

    lines.extend(["  </channel>", "</rss>"])
    OUTPUT.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    write_rss(collect_posts())


if __name__ == "__main__":
    main()
