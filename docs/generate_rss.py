#!/usr/bin/env python3

"""Generate a deterministic RSS feed for commonware blog posts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import format_datetime
from html.parser import HTMLParser
from pathlib import Path
import re
from xml.sax.saxutils import escape


DOCS_ROOT = Path(__file__).resolve().parent
BLOGS_DIR = DOCS_ROOT / "blogs"
BASE_URL = "https://commonware.xyz"
FEED_PATH = DOCS_ROOT / "feed.xml"
CHANNEL_TITLE = "commonware"
CHANNEL_DESCRIPTION = "Blog posts from commonware."


def normalize_text(text: str) -> str:
    """Collapse whitespace from HTML metadata onto a single line."""
    return re.sub(r"\s+", " ", text).strip()


class MetaParser(HTMLParser):
    """Collect meta tag name/property and content attributes from HTML."""

    def __init__(self) -> None:
        super().__init__()
        self.metas: dict[str, str] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "meta":
            return

        parsed = {key: value for key, value in attrs if value is not None}
        content = parsed.get("content")
        if content is None:
            return

        if "property" in parsed:
            self.metas[parsed["property"]] = content
        if "name" in parsed:
            self.metas[parsed["name"]] = content


@dataclass(frozen=True)
class BlogPost:
    slug: str
    title: str
    url: str
    description: str
    author: str
    published: datetime

    @classmethod
    def from_html(cls, path: Path) -> BlogPost:
        parser = MetaParser()
        parser.feed(path.read_text(encoding="utf-8"))

        title = parser.metas.get("og:title")
        url = parser.metas.get("og:url")
        description = parser.metas.get("og:description") or parser.metas.get("description")
        author = parser.metas.get("author") or parser.metas.get("article:author", "")
        published_raw = parser.metas.get("article:published_time")

        missing = [
            field
            for field, value in (
                ("og:title", title),
                ("og:url", url),
                ("description", description),
                ("article:published_time", published_raw),
            )
            if not value
        ]
        if missing:
            raise ValueError(f"{path}: missing required metadata: {', '.join(missing)}")

        published = datetime.fromisoformat(published_raw.replace("Z", "+00:00"))
        return cls(
            slug=path.stem,
            title=normalize_text(title),
            url=url,
            description=normalize_text(description),
            author=normalize_text(author),
            published=published,
        )


def collect_posts() -> list[BlogPost]:
    """Return blog posts sorted newest-first, then by slug for stability."""
    posts = [BlogPost.from_html(path) for path in sorted(BLOGS_DIR.glob("*.html"))]
    posts.sort(key=lambda post: (post.published, post.slug), reverse=True)
    return posts


def format_rfc822(when: datetime) -> str:
    """Format a timezone-aware datetime for RSS pubDate fields."""
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return format_datetime(when, usegmt=True)


def write_feed(posts: list[BlogPost]) -> None:
    """Write feed.xml with the provided blog posts."""
    last_build = format_rfc822(posts[0].published) if posts else format_rfc822(
        datetime.now(timezone.utc)
    )

    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">',
        "  <channel>",
        f"    <title>{escape(CHANNEL_TITLE)}</title>",
        f"    <link>{escape(BASE_URL)}</link>",
        f"    <description>{escape(CHANNEL_DESCRIPTION)}</description>",
        "    <language>en</language>",
        f"    <lastBuildDate>{last_build}</lastBuildDate>",
        f'    <atom:link href="{escape(f"{BASE_URL}/feed.xml")}" rel="self" type="application/rss+xml" />',
    ]

    for post in posts:
        lines.extend(
            [
                "    <item>",
                f"      <title>{escape(post.title)}</title>",
                f"      <link>{escape(post.url)}</link>",
                f'      <guid isPermaLink="true">{escape(post.url)}</guid>',
                f"      <description>{escape(post.description)}</description>",
                f"      <pubDate>{format_rfc822(post.published)}</pubDate>",
                f"      <author>{escape(post.author)}</author>",
                "    </item>",
            ]
        )

    lines.extend(["  </channel>", "</rss>", ""])
    FEED_PATH.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    write_feed(collect_posts())


if __name__ == "__main__":
    main()
