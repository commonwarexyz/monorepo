#!/usr/bin/env python3
"""Regenerate the checked-in Curve25519 test vectors from pinned sources."""

from __future__ import annotations

import argparse
import difflib
import hashlib
import re
import sys
import urllib.request
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Source:
    name: str
    url: str
    sha256: str


RFC8032 = Source(
    name="RFC 8032",
    url="https://www.rfc-editor.org/rfc/rfc8032.txt",
    sha256="ed63657ff389301282b169b0abde9b5dd2c7e4d524fdfa5da6ff3094fc93c4c3",
)
RFC7748 = Source(
    name="RFC 7748",
    url="https://www.rfc-editor.org/rfc/rfc7748.txt",
    sha256="279ca0ecc5e92e2962e27b846986aeb74729d9dd34bd4a04a362f80dcb596ad3",
)
ZIP215 = Source(
    name="ZIP 215 test vectors",
    url=(
        "https://gist.githubusercontent.com/hdevalence/"
        "93ed42d17ecab8e42138b213812c8cc7/raw/"
        "83851a92916d3289b73aaa9ec64b988aae678eb2/gistfile1.txt"
    ),
    sha256="cd6ece09eb33e878da251103c5ca754e1b1b261402b9987cdc102d30942aba08",
)

OUTPUT = Path(__file__).resolve().parent / "src" / "test" / "vectors.rs"
HEX_LINE = re.compile(r"[0-9a-f]+")
ZIP215_SPEC_URL = "https://zips.z.cash/zip-0215"


@dataclass(frozen=True)
class Ed25519Vector:
    name: str
    secret_key: str
    public_key: str
    message: str
    signature: str


@dataclass(frozen=True)
class X25519Vector:
    scalar: str
    u_coordinate: str
    output: str


@dataclass(frozen=True)
class X25519DiffieHellmanVector:
    alice_secret: str
    alice_public: str
    bob_secret: str
    bob_public: str
    shared_secret: str


def fetch(source: Source) -> str:
    request = urllib.request.Request(
        source.url,
        headers={"User-Agent": "commonware-curve25519-test-vector-generator"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        data = response.read()
    digest = hashlib.sha256(data).hexdigest()
    if digest != source.sha256:
        raise ValueError(
            f"{source.name} digest changed: expected {source.sha256}, got {digest}"
        )
    return data.decode("ascii")


def strip_rfc_page_headers(text: str, title: str, authors: str) -> str:
    return "\n".join(
        line
        for line in text.splitlines()
        if title not in line and authors not in line
    )


def hex_lines(text: str) -> str:
    return "".join(
        line.strip() for line in text.splitlines() if HEX_LINE.fullmatch(line.strip())
    )


def field(block: str, start: str, end: str | None = None) -> str:
    value = block.split(start, 1)[1]
    if end is not None:
        value = value.split(end, 1)[0]
    return hex_lines(value)


def parse_ed25519(text: str) -> list[Ed25519Vector]:
    text = strip_rfc_page_headers(text, "RFC 8032", "Josefsson & Liusvaara")
    section = text.split("\n7.1.  Test Vectors for Ed25519\n", 1)[1]
    section = section.split("\n7.2.  Test Vectors for Ed25519ctx\n", 1)[0]
    vectors = []
    for raw_block in section.split("-----TEST ")[1:]:
        name, block = raw_block.split("\n", 1)
        length_match = re.search(r"MESSAGE \(length ([0-9]+) bytes?\):", block)
        if length_match is None:
            raise ValueError(f"missing message length in RFC 8032 test {name}")
        message = hex_lines(block[length_match.end() :].split("SIGNATURE:", 1)[0])
        expected_length = int(length_match.group(1))
        if len(message) != expected_length * 2:
            raise ValueError(
                f"RFC 8032 test {name} message has {len(message) // 2} bytes, "
                f"expected {expected_length}"
            )
        vector = Ed25519Vector(
            name=name.strip(),
            secret_key=field(block, "SECRET KEY:", "PUBLIC KEY:"),
            public_key=field(block, "PUBLIC KEY:", "MESSAGE (length"),
            message=message,
            signature=field(block, "SIGNATURE:"),
        )
        if not (
            len(vector.secret_key) == 64
            and len(vector.public_key) == 64
            and len(vector.signature) == 128
        ):
            raise ValueError(f"invalid field width in RFC 8032 test {name}")
        vectors.append(vector)
    if len(vectors) != 5:
        raise ValueError(f"expected 5 RFC 8032 Ed25519 vectors, got {len(vectors)}")
    return vectors


def parse_x25519(text: str) -> tuple[list[X25519Vector], X25519DiffieHellmanVector]:
    text = strip_rfc_page_headers(text, "RFC 7748", "Langley, et al.")
    section = text.split("\n5.2.  Test Vectors\n", 1)[1]
    section = section.split("\n6.  Diffie-Hellman\n", 1)[0]
    direct = section.split("\n   X25519:\n", 1)[1].split("\n   X448:\n", 1)[0]
    pattern = re.compile(
        r"Input scalar:\s*\n\s*([0-9a-f]{64})"
        r".*?Input u-coordinate:\s*\n\s*([0-9a-f]{64})"
        r".*?Output u-coordinate:\s*\n\s*([0-9a-f]{64})",
        re.DOTALL,
    )
    vectors = [X25519Vector(*match) for match in pattern.findall(direct)]
    if len(vectors) != 2:
        raise ValueError(f"expected 2 direct RFC 7748 X25519 vectors, got {len(vectors)}")

    section = text.split("\n6.1.  Curve25519\n", 1)[1]
    section = section.split("\n6.2.  Curve448\n", 1)[0]
    diffie_hellman = X25519DiffieHellmanVector(
        alice_secret=field(
            section,
            "Alice's private key, a:",
            "Alice's public key, X25519(a, 9):",
        ),
        alice_public=field(
            section,
            "Alice's public key, X25519(a, 9):",
            "Bob's private key, b:",
        ),
        bob_secret=field(
            section,
            "Bob's private key, b:",
            "Bob's public key, X25519(b, 9):",
        ),
        bob_public=field(
            section,
            "Bob's public key, X25519(b, 9):",
            "Their shared secret, K:",
        ),
        shared_secret=field(section, "Their shared secret, K:", "6.2."),
    )
    if any(len(value) != 64 for value in diffie_hellman.__dict__.values()):
        raise ValueError("invalid field width in RFC 7748 Diffie-Hellman vector")
    return vectors, diffie_hellman


def parse_zip215_points(text: str) -> list[str]:
    pattern = re.compile(
        r'TestCase \{\s*vk_bytes: "([0-9a-f]{64})",\s*'
        r'sig_bytes: "([0-9a-f]{128})",\s*'
        r"valid_legacy: (?:true|false),\s*valid_zip215: true,\s*\}",
        re.DOTALL,
    )
    cases = pattern.findall(text)
    if len(cases) != 196:
        raise ValueError(f"expected 196 ZIP 215 vectors, got {len(cases)}")
    if any(signature[64:] != "00" * 32 for _, signature in cases):
        raise ValueError("a ZIP 215 vector has a nonzero scalar")

    public_keys = list(dict.fromkeys(public_key for public_key, _ in cases))
    r_encodings = list(dict.fromkeys(signature[:64] for _, signature in cases))
    if public_keys != r_encodings or len(public_keys) != 14:
        raise ValueError("ZIP 215 vectors do not contain the expected 14 point encodings")
    expected = [(public_key, r + "00" * 32) for public_key in public_keys for r in r_encodings]
    if cases != expected:
        raise ValueError("ZIP 215 vectors are not the expected 14-by-14 matrix")
    return public_keys


def hex_expr(value: str, indent: str) -> str:
    if not value:
        return "commonware_formatting::hex!()"
    if len(value) <= 4:
        return f'commonware_formatting::hex!("0x{value}")'
    chunks = [value[i : i + 64] for i in range(0, len(value), 64)]
    lines = ["commonware_formatting::hex!("]
    for index, chunk in enumerate(chunks):
        prefix = "0x" if index == 0 else ""
        lines.append(f'{indent}    "{prefix}{chunk}"')
    lines.append(f"{indent})")
    return "\n".join(lines)


def hex_field(name: str, value: str, indent: str, reference: bool = False) -> str:
    reference_prefix = "&" if reference else ""
    return f"{indent}{name}: {reference_prefix}{hex_expr(value, indent)},"


def render(
    ed25519: list[Ed25519Vector],
    x25519: list[X25519Vector],
    diffie_hellman: X25519DiffieHellmanVector,
    zip215_points: list[str],
) -> str:
    lines = [
        "// Generated by cryptography/curve25519/generate_test_vectors.py.",
        "// Do not edit manually.",
        "//",
        f"// {RFC8032.name}: {RFC8032.url}",
        f"// {RFC7748.name}: {RFC7748.url}",
        f"// ZIP 215 specification: {ZIP215_SPEC_URL}",
        f"// {ZIP215.name}: {ZIP215.url}",
        "",
        "pub(super) struct Ed25519Vector {",
        "    pub(super) name: &'static str,",
        "    pub(super) secret_key: [u8; 32],",
        "    pub(super) public_key: [u8; 32],",
        "    pub(super) message: &'static [u8],",
        "    pub(super) signature: [u8; 64],",
        "}",
        "",
        "pub(super) const RFC8032_ED25519: &[Ed25519Vector] = &[",
    ]
    for vector in ed25519:
        lines.extend(
            [
                "    Ed25519Vector {",
                f'        name: "{vector.name}",',
                hex_field("secret_key", vector.secret_key, "        "),
                hex_field("public_key", vector.public_key, "        "),
                hex_field("message", vector.message, "        ", reference=True),
                hex_field("signature", vector.signature, "        "),
                "    },",
            ]
        )
    lines.extend(
        [
            "];",
            "",
            "pub(super) struct X25519Vector {",
            "    pub(super) scalar: [u8; 32],",
            "    pub(super) u_coordinate: [u8; 32],",
            "    pub(super) output: [u8; 32],",
            "}",
            "",
            "pub(super) const RFC7748_X25519: &[X25519Vector] = &[",
        ]
    )
    for vector in x25519:
        lines.extend(
            [
                "    X25519Vector {",
                hex_field("scalar", vector.scalar, "        "),
                hex_field("u_coordinate", vector.u_coordinate, "        "),
                hex_field("output", vector.output, "        "),
                "    },",
            ]
        )
    lines.extend(
        [
            "];",
            "",
            "pub(super) struct X25519DiffieHellmanVector {",
            "    pub(super) alice_secret: [u8; 32],",
            "    pub(super) alice_public: [u8; 32],",
            "    pub(super) bob_secret: [u8; 32],",
            "    pub(super) bob_public: [u8; 32],",
            "    pub(super) shared_secret: [u8; 32],",
            "}",
            "",
            "pub(super) const RFC7748_X25519_DIFFIE_HELLMAN: X25519DiffieHellmanVector =",
            "    X25519DiffieHellmanVector {",
            hex_field("alice_secret", diffie_hellman.alice_secret, "        "),
            hex_field("alice_public", diffie_hellman.alice_public, "        "),
            hex_field("bob_secret", diffie_hellman.bob_secret, "        "),
            hex_field("bob_public", diffie_hellman.bob_public, "        "),
            hex_field("shared_secret", diffie_hellman.shared_secret, "        "),
            "    };",
            "",
            f"pub(super) const ZIP215_POINTS: [[u8; 32]; {len(zip215_points)}] = [",
        ]
    )
    for point in zip215_points:
        lines.append(f"    {hex_expr(point, '    ')},")
    lines.extend(["];", ""])
    return "\n".join(lines)


def generate() -> str:
    ed25519 = parse_ed25519(fetch(RFC8032))
    x25519, diffie_hellman = parse_x25519(fetch(RFC7748))
    zip215_points = parse_zip215_points(fetch(ZIP215))
    return render(ed25519, x25519, diffie_hellman, zip215_points)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail if the checked-in vectors differ from regenerated output",
    )
    args = parser.parse_args()
    generated = generate()

    if args.check:
        checked_in = OUTPUT.read_text(encoding="ascii") if OUTPUT.exists() else ""
        if checked_in == generated:
            return 0
        sys.stdout.writelines(
            difflib.unified_diff(
                checked_in.splitlines(keepends=True),
                generated.splitlines(keepends=True),
                fromfile=str(OUTPUT),
                tofile="regenerated",
            )
        )
        return 1

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT.open("w", encoding="ascii", newline="\n") as output:
        output.write(generated)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
