"""Regression tests for deterministic RSS generation."""

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import generate_rss


class GenerateRSSTest(unittest.TestCase):
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
                with patch.object(Path, "glob", return_value=iter(paths)):
                    first = generate_rss.collect_posts()
                with patch.object(Path, "glob", return_value=iter(reversed(paths))):
                    second = generate_rss.collect_posts()
            self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
