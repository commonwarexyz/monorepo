#!/bin/bash
# usage: multimmit-measure/layout.sh <campaign-dir>
# Creates the campaign directory the driver expects: tools/, status/ (progress state and live page),
# provenance/ (source revision and binary hashes), build/ (binaries), testbeds/, runs/.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/.." && pwd)
mkdir -p "$1"/{tools,status/src,provenance,build,testbeds/global,testbeds/na,runs}
AR=$(cd "$1" && pwd)
for f in campaign.py analyze.py discover.py detach.py reanalyze.py build_summary.py create.sh stage.sh pull_store.sh bundle.sh; do
  cp "$HERE/$f" "$AR/tools/$f"
done
cp "$HERE/status.py" "$AR/status/status.py"
chmod +x "$AR"/tools/*.sh
# The live page needs only these templates; plain stubs give a bare page, progress.json holds the state.
[ -f "$AR/status/src/plan_css.css" ] || echo "body{font:14px monospace}" > "$AR/status/src/plan_css.css"
[ -f "$AR/status/src/plan_body.html" ] || echo "<h1>Multimmit measurement</h1><pre id=p></pre>" > "$AR/status/src/plan_body.html"
[ -f "$AR/status/src/map.json" ] || echo "{}" > "$AR/status/src/map.json"
[ -f "$AR/status/src/plan_js.html" ] || cat > "$AR/status/src/plan_js.html" <<'EOF'
<script>const P = __PROGRESS__; document.getElementById("p").textContent = JSON.stringify(P, null, 1);</script></body></html>
EOF
# The source identity: the repository's tree without this folder, which is the measured tree.
python3 - "$AR" "$REPO" <<'EOF'
import json, subprocess, sys
ar, repo = sys.argv[1], sys.argv[2]
def git(*a, stdin=None):
    r = subprocess.run(["git", "-C", repo, *a], capture_output=True, text=True, input=stdin)
    return r.stdout.strip() if r.returncode == 0 else None
commit = git("rev-parse", "HEAD")
listing = git("ls-tree", "HEAD")
tree = git("mktree", stdin="\n".join(l for l in listing.splitlines() if not l.endswith("\tmultimmit-measure")) + "\n") if listing else None
json.dump({"repository": "this repository", "commit": commit or "unknown", "tree": tree or "unknown"},
          open(ar + "/provenance/source.json", "w"), indent=1)
EOF
echo "laid out $AR; next: README step 4 (binaries and their hashes)"
