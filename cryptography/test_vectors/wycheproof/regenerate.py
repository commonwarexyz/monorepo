#!/usr/bin/env python3
"""Regenerate `cryptography/src/ed25519/wycheproof_vectors.rs` from the
vendored Project Wycheproof Ed25519 test-vector JSON.

The regenerated Rust file is the only source of test data consumed at
`cargo test` time; this avoids adding a JSON parser to the crate's dev
dependencies.

Usage (from the repo root):

    python3 cryptography/test_vectors/wycheproof/regenerate.py

The script will:

  1. Re-download `ed25519_test.json` from the pinned upstream commit
     (set via `WYCHEPROOF_COMMIT` below) into the vendored location,
  2. Emit `cryptography/src/ed25519/wycheproof_vectors.rs`.

Both files are committed to the repository. Bumping the pinned commit
is a deliberate two-step:

  1. Update `WYCHEPROOF_COMMIT` here.
  2. Re-run this script, audit the JSON diff, and re-run
     `just test -p commonware-cryptography ed25519::wycheproof` to
     confirm no new ZIP215 deviations have been introduced.
"""

import json
import pathlib
import subprocess
import sys
import urllib.request

# Pinned upstream Wycheproof commit. Bumping this is a deliberate change
# that must be paired with a re-audit of any new ZIP215 deviations.
WYCHEPROOF_COMMIT = "6d9d6de30f02e229dfc160323722c3ddac866181"
UPSTREAM_PATH = "testvectors_v1/ed25519_test.json"
UPSTREAM_URL = (
    f"https://raw.githubusercontent.com/C2SP/wycheproof/{WYCHEPROOF_COMMIT}/{UPSTREAM_PATH}"
)
PERMALINK = (
    f"https://github.com/C2SP/wycheproof/blob/{WYCHEPROOF_COMMIT}/{UPSTREAM_PATH}"
)

REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
JSON_PATH = REPO_ROOT / "cryptography" / "test_vectors" / "wycheproof" / "ed25519_test.json"
RS_PATH = REPO_ROOT / "cryptography" / "src" / "ed25519" / "wycheproof_vectors.rs"


def hex_to_bytes(hex_str: str) -> bytes:
    # Wycheproof uses plain lowercase hex with even length; reject anything else
    # so a malformed upstream change surfaces here instead of as a confusing
    # compile failure.
    return bytes.fromhex(hex_str)


def rust_byte_literal(data: bytes) -> str:
    if not data:
        return "&[]"
    return "&[" + ", ".join(f"0x{b:02x}" for b in data) + "]"


def rust_str_literal(s: str) -> str:
    # JSON strings can contain any unicode; round-trip through json.dumps so
    # backslashes, quotes, and non-ASCII characters are escaped correctly.
    return json.dumps(s, ensure_ascii=False)


def fetch_json() -> dict:
    """Download the pinned vector file. Falls back to `curl` if Python's
    `urllib` cannot validate TLS certificates (a common situation on macOS
    with the python.org Python build, which does not use the system trust
    store)."""
    print(f"Fetching {UPSTREAM_URL}", file=sys.stderr)
    JSON_PATH.parent.mkdir(parents=True, exist_ok=True)
    try:
        with urllib.request.urlopen(UPSTREAM_URL) as resp:
            raw = resp.read()
    except Exception as exc:
        print(f"  urllib failed ({exc!r}); retrying with curl", file=sys.stderr)
        raw = subprocess.check_output(
            ["curl", "-sSfL", UPSTREAM_URL],
        )
    JSON_PATH.write_bytes(raw)
    return json.loads(raw)


def main() -> int:
    doc = fetch_json()
    assert doc["algorithm"] == "EDDSA", doc["algorithm"]

    lines: list[str] = []
    lines.append("// This file is auto-generated. Do not edit by hand.")
    lines.append("//")
    lines.append(
        "// Source: Project Wycheproof, pinned at commit"
    )
    lines.append(f"//   {WYCHEPROOF_COMMIT}")
    lines.append(f"// File:   {UPSTREAM_PATH}")
    lines.append(f"// Permalink: {PERMALINK}")
    lines.append("//")
    lines.append("// To regenerate, run:")
    lines.append("//   python3 cryptography/test_vectors/wycheproof/regenerate.py")
    lines.append("")
    lines.append("use super::wycheproof::{Vector, Verdict};")
    lines.append("")
    lines.append(
        "/// `numberOfTests` field reported by the upstream JSON at the pinned commit."
    )
    lines.append(
        "/// Used by `vector_count_matches_upstream` to guard against accidental"
    )
    lines.append("/// truncation of the generated array below.")
    lines.append(
        f"pub(super) const NUMBER_OF_TESTS: usize = {int(doc['numberOfTests'])};"
    )
    lines.append("")
    lines.append("pub(super) const VECTORS: &[Vector] = &[")

    emitted = 0
    for group in doc["testGroups"]:
        pk_hex = group["publicKey"]["pk"]
        pk_bytes = hex_to_bytes(pk_hex)
        for test in group["tests"]:
            result = test["result"]
            if result == "valid":
                verdict = "Verdict::Valid"
            elif result == "invalid":
                verdict = "Verdict::Invalid"
            elif result == "acceptable":
                # Upstream uses "acceptable" for cases where either accept or
                # reject is conformant. Wycheproof's Ed25519 vectors at the
                # pinned commit contain none of these, so flag if that changes.
                raise SystemExit(
                    f"unexpected 'acceptable' verdict at tcId={test['tcId']}; "
                    "extend the verdict enum if upstream now uses this class"
                )
            else:
                raise SystemExit(f"unknown result class: {result!r}")

            msg_bytes = hex_to_bytes(test["msg"])
            sig_bytes = hex_to_bytes(test["sig"])
            flags = test.get("flags", [])
            flag_lits = ", ".join(rust_str_literal(f) for f in flags)

            lines.append("    Vector {")
            lines.append(f"        tc_id: {int(test['tcId'])},")
            lines.append(f"        comment: {rust_str_literal(test['comment'])},")
            lines.append(f"        public_key: {rust_byte_literal(pk_bytes)},")
            lines.append(f"        msg: {rust_byte_literal(msg_bytes)},")
            lines.append(f"        sig: {rust_byte_literal(sig_bytes)},")
            lines.append(f"        result: {verdict},")
            lines.append(f"        flags: &[{flag_lits}],")
            lines.append("    },")
            emitted += 1

    lines.append("];")
    lines.append("")

    if emitted != doc["numberOfTests"]:
        raise SystemExit(
            f"emitted {emitted} vectors but numberOfTests = {doc['numberOfTests']}"
        )

    RS_PATH.write_text("\n".join(lines))
    print(f"Wrote {RS_PATH} ({emitted} vectors)", file=sys.stderr)

    # Apply rustfmt so the generated file matches the in-repo style without
    # requiring a follow-up `just fix-fmt`.
    try:
        subprocess.run(
            ["rustfmt", "--edition", "2021", str(RS_PATH)],
            check=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError) as exc:
        print(
            f"warning: rustfmt did not run cleanly ({exc!r}); "
            "run `just fix-fmt` before committing",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
