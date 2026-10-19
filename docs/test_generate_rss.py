"""Regression tests for deterministic RSS generation."""

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from xml.etree import ElementTree

import generate_rss


class GenerateRSSTest(unittest.TestCase):
    def test_html_posts_and_markdown_duplicates(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "only.html").write_text(
                '<meta property="og:title" content="HTML &amp; RSS">'
                '<meta property="og:description" content="An HTML post">'
                '<meta property="article:published_time" content="2026-02-01T00:00:00Z">'
                '<meta property="og:url" content="https://commonware.xyz/blogs/only">',
                encoding="utf-8",
            )
            (root / "duplicate.html").write_text(
                '<meta property="og:title" content="Old title">'
                '<meta property="og:description" content="Old description">'
                '<meta property="article:published_time" content="2026-01-01T00:00:00Z">'
                '<meta property="og:url" content="https://commonware.xyz/blogs/duplicate">',
                encoding="utf-8",
            )
            (root / "duplicate.md").write_text(
                '---\ntitle: "Source title"\ndescription: "Source description"\n'
                'published-time: "2026-01-01T00:00:00Z"\n'
                'url: "https://commonware.xyz/blogs/duplicate"\n---\n',
                encoding="utf-8",
            )
            (root / "incomplete.html").write_text('<title>Not a post</title>')
            with patch.object(generate_rss, "BLOGS_ROOT", root):
                posts = generate_rss.collect_posts()
            self.assertEqual(
                [post[1]["title"] for post in posts], ["HTML & RSS", "Source title"]
            )
            output = root / "rss.xml"
            with patch.object(generate_rss, "OUTPUT", output):
                generate_rss.write_rss(posts)
            channel = ElementTree.parse(output).getroot().find("channel")
            self.assertEqual(channel.findtext("link"), "https://commonware.xyz")
            self.assertEqual(len(channel.findall("item")), 2)

    def test_equal_dates_have_stable_order(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            paths = [root / "a.md", root / "b.md"]
            for path in paths:
                path.write_text(
                    f'---\ntitle: "{path.stem}"\ndescription: "Test"\n'
                    'published-time: "2026-01-01T00:00:00Z"\n'
                    f'url: "https://commonware.xyz/blogs/{path.stem}"\n---\n',
                    encoding="utf-8",
                )
            with patch.object(generate_rss, "BLOGS_ROOT", root):
                with patch.object(
                    Path, "glob",
                    side_effect=lambda pattern: iter(paths) if pattern == "*.md" else iter(()),
                ):
                    first = generate_rss.collect_posts()
                with patch.object(
                    Path, "glob",
                    side_effect=lambda pattern: iter(reversed(paths)) if pattern == "*.md" else iter(()),
                ):
                    second = generate_rss.collect_posts()
            self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
