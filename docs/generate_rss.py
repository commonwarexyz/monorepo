#!/usr/bin/env python3

"""Generate an RSS 2.0 feed for Commonware blog posts."""

from __future__ import annotations

from datetime import datetime, timezone
from email.utils import format_datetime
from html.parser import HTMLParser
from pathlib import Path
from xml.sax.saxutils import escape


DOCS_ROOT = Path(__file__).resolve().parent
BLOGS_ROOT = DOCS_ROOT / "blogs"
OUTPUT = DOCS_ROOT / "rss.xml"
CHANNEL_TITLE = "Commonware Blog"
CHANNEL_LINK = "https://commonware.xyz"
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


class BlogMetadataParser(HTMLParser):
    """Read the same Open Graph metadata used by HTML-authored posts."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.metadata: dict[str, str] = {}

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        fields = {
            "og:title": "title",
            "og:description": "description",
            "og:url": "url",
            "article:published_time": "published-time",
        }
        if tag == "meta":
            field = fields.get(attributes.get("property"))
            content = attributes.get("content")
            if field and content:
                self.metadata[field] = content


def parse_html(path: Path) -> dict[str, str]:
    """Extract publication metadata from a blog HTML document."""
    parser = BlogMetadataParser()
    parser.feed(path.read_text(encoding="utf-8"))
    return parser.metadata


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
    by_url: dict[str, tuple[datetime, dict[str, str]]] = {}
    required = {"title", "description", "published-time", "url"}

    # Read HTML first so markdown sources replace their generated HTML copies.
    for extension, parse in (("html", parse_html), ("md", parse_frontmatter)):
        for path in sorted(BLOGS_ROOT.glob(f"*.{extension}")):
            metadata = parse(path)
            if not required.issubset(metadata):
                continue
            by_url[metadata["url"]] = (
                parse_published_time(metadata["published-time"]), metadata
            )

    posts = sorted(by_url.values(), key=lambda item: item[1]["url"])
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
