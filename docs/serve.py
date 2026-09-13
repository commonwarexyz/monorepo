#!/usr/bin/env python3

"""Serve the docs site with live reload.

Rebuilds markdown when a source file changes, then refreshes the browser.
"""

from __future__ import annotations

import argparse
import http.server
import os
import subprocess
import threading
import time
from pathlib import Path
from urllib.parse import unquote, urlparse


DOCS_ROOT = Path(__file__).resolve().parent
SKIP_DIRS = {".venv", "code", ".git"}
REBUILD_SUFFIXES = {".md"}
REBUILD_NAMES = {"template.html"}
WATCH_SUFFIXES = {".md", ".html", ".css", ".js"}
POLL_SECONDS = 0.4
INJECT = b"""<script>
(function () {
  let version = null;
  setInterval(async () => {
    try {
      const next = await (await fetch("/__livereload")).text();
      if (version === null) version = next;
      else if (next !== version) location.reload();
    } catch (e) {}
  }, 400);
})();
</script>
"""


def collect_mtimes() -> dict[Path, float]:
    mtimes = {}
    for path in DOCS_ROOT.rglob("*"):
        if not path.is_file() or SKIP_DIRS.intersection(path.parts):
            continue
        if path.suffix in WATCH_SUFFIXES or path.name in REBUILD_NAMES:
            mtimes[path] = path.stat().st_mtime
    return mtimes


def rebuild() -> None:
    print("Rebuilding markdown...")
    subprocess.run(["make", "markdown"], cwd=DOCS_ROOT, check=False)


class State:
    def __init__(self) -> None:
        self.version = 0
        self.lock = threading.Lock()

    def bump(self) -> None:
        with self.lock:
            self.version += 1

    def current(self) -> int:
        with self.lock:
            return self.version


def watch(state: State) -> None:
    previous = collect_mtimes()
    while True:
        time.sleep(POLL_SECONDS)
        current = collect_mtimes()
        changed = [path for path, mtime in current.items() if previous.get(path) != mtime]
        if not changed:
            previous = current
            continue
        if any(path.suffix in REBUILD_SUFFIXES or path.name in REBUILD_NAMES for path in changed):
            rebuild()
            current = collect_mtimes()
        state.bump()
        print("Reload: " + ", ".join(str(path.relative_to(DOCS_ROOT)) for path in changed))
        previous = current


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, state: State, **kwargs):
        self.state = state
        super().__init__(*args, directory=str(DOCS_ROOT), **kwargs)

    def do_GET(self) -> None:
        if self.path == "/__livereload":
            body = str(self.state.current()).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        parsed = urlparse(self.path)
        rel = unquote(parsed.path).lstrip("/")
        path = (DOCS_ROOT / rel).resolve()
        if path.is_dir():
            path = path / "index.html"
        if path.suffix == ".html" and path.is_file() and path.is_relative_to(DOCS_ROOT):
            data = path.read_bytes()
            if b"</body>" in data:
                data = data.replace(b"</body>", INJECT + b"</body>", 1)
            else:
                data += INJECT
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return

        super().do_GET()

    def log_message(self, format: str, *args) -> None:
        if args and str(args[0]).startswith("GET /__livereload"):
            return
        super().log_message(format, *args)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()

    os.chdir(DOCS_ROOT)
    rebuild()

    state = State()
    threading.Thread(target=watch, args=(state,), daemon=True).start()

    def handler(*handler_args, **handler_kwargs):
        return Handler(*handler_args, state=state, **handler_kwargs)

    server = http.server.ThreadingHTTPServer(("127.0.0.1", args.port), handler)
    print(f"Serving docs at http://127.0.0.1:{args.port}/")
    print("Saving a .md, .css, or .js file rebuilds and refreshes the browser.")
    server.serve_forever()


if __name__ == "__main__":
    main()
