#!/usr/bin/env python3
"""Regenerate the checked-in BLS test vectors from pinned RFC 9380."""

from __future__ import annotations

import argparse
import difflib
import hashlib
import re
import sys
import urllib.request
from dataclasses import dataclass
from pathlib import Path


RFC9380_URL = "https://www.rfc-editor.org/rfc/rfc9380.txt"
RFC9380_SHA256 = "a2e6ab02b2117d6f52ac293020857752972b2e23ae005c33f612e40436ff4b6d"
OUTPUT = Path(__file__).resolve().parent / "src" / "test" / "vectors.rs"
HEX_LINE = re.compile(r"[0-9a-f]+")
G1_DST = "QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_"
G2_DST = "QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_"
XMD_DST = "QUUX-V01-CS02-with-expander-SHA256-128"


@dataclass(frozen=True)
class G1Vector:
    message: str
    x: str
    y: str


@dataclass(frozen=True)
class G2Vector:
    message: str
    x_c0: str
    x_c1: str
    y_c0: str
    y_c1: str


@dataclass(frozen=True)
class XmdVector:
    message: str
    output: str


def fetch() -> str:
    request = urllib.request.Request(
        RFC9380_URL,
        headers={"User-Agent": "commonware-bls-test-vector-generator"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        data = response.read()
    digest = hashlib.sha256(data).hexdigest()
    if digest != RFC9380_SHA256:
        raise ValueError(
            f"RFC 9380 digest changed: expected {RFC9380_SHA256}, got {digest}"
        )
    return data.decode("utf-8-sig")


def strip_page_headers(text: str) -> str:
    return "\n".join(
        line
        for line in text.splitlines()
        if "RFC 9380" not in line and "Faz-Hernandez, et al." not in line
    )


def section(text: str, start: str, end: str) -> str:
    try:
        return text.split(f"\n{start}\n", 1)[1].split(f"\n{end}\n", 1)[0]
    except IndexError as error:
        raise ValueError(f"missing RFC 9380 section {start}") from error


def wrapped(block: str, start: str, end: str) -> str:
    try:
        value = block.split(start, 1)[1] if start else block
        value = value.split(end, 1)[0]
    except IndexError as error:
        raise ValueError(f"missing field {start.strip()}") from error
    return "".join(line.strip() for line in value.splitlines())


def hex_field(block: str, start: str, end: str) -> str:
    try:
        value = block.split(start, 1)[1].split(end, 1)[0]
    except IndexError as error:
        raise ValueError(f"missing field {start.strip()}") from error
    return "".join(
        line.strip() for line in value.splitlines() if HEX_LINE.fullmatch(line.strip())
    )


def fp2_field(block: str, start: str, end: str) -> tuple[str, str]:
    try:
        value = block.split(start, 1)[1].split(end, 1)[0]
        c0, c1 = value.split("+ I *", 1)
    except (IndexError, ValueError) as error:
        raise ValueError(f"invalid extension field {start.strip()}") from error
    return (
        "".join(line.strip() for line in c0.splitlines() if HEX_LINE.fullmatch(line.strip())),
        "".join(line.strip() for line in c1.splitlines() if HEX_LINE.fullmatch(line.strip())),
    )


def validate_messages(messages: list[str], suite: str) -> None:
    if [len(message) for message in messages] != [0, 3, 16, 133, 517]:
        raise ValueError(f"unexpected message lengths in {suite}")
    if messages[1:3] != ["abc", "abcdef0123456789"]:
        raise ValueError(f"unexpected short messages in {suite}")
    if messages[3] != "q128_" + "q" * 128 or messages[4] != "a512_" + "a" * 512:
        raise ValueError(f"unexpected long messages in {suite}")


def parse_g1(text: str) -> tuple[str, list[G1Vector]]:
    body = section(
        text,
        "J.9.1.  BLS12381G1_XMD:SHA-256_SSWU_RO_",
        "J.9.2.  BLS12381G1_XMD:SHA-256_SSWU_NU_",
    )
    dst = wrapped(body, "   dst     =", "\n\n")
    vectors = []
    for block in body.split("\n   msg     =")[1:]:
        vector = G1Vector(
            message=wrapped(block, "", "\n   P.x"),
            x=hex_field(block, "   P.x     =", "\n   P.y"),
            y=hex_field(block, "   P.y     =", "\n   u[0]"),
        )
        if len(vector.x) != 96 or len(vector.y) != 96:
            raise ValueError("invalid G1 coordinate width")
        bytes.fromhex(vector.x + vector.y)
        vectors.append(vector)
    if len(vectors) != 5:
        raise ValueError(f"expected 5 RFC 9380 G1 vectors, got {len(vectors)}")
    validate_messages([vector.message for vector in vectors], "G1")
    return dst, vectors


def parse_g2(text: str) -> tuple[str, list[G2Vector]]:
    body = section(
        text,
        "J.10.1.  BLS12381G2_XMD:SHA-256_SSWU_RO_",
        "J.10.2.  BLS12381G2_XMD:SHA-256_SSWU_NU_",
    )
    dst = wrapped(body, "   dst     =", "\n\n")
    vectors = []
    for block in body.split("\n   msg     =")[1:]:
        x_c0, x_c1 = fp2_field(block, "   P.x     =", "\n   P.y")
        y_c0, y_c1 = fp2_field(block, "   P.y     =", "\n   u[0]")
        vector = G2Vector(
            message=wrapped(block, "", "\n   P.x"),
            x_c0=x_c0,
            x_c1=x_c1,
            y_c0=y_c0,
            y_c1=y_c1,
        )
        if any(len(value) != 96 for value in (x_c0, x_c1, y_c0, y_c1)):
            raise ValueError("invalid G2 coordinate width")
        bytes.fromhex(x_c0 + x_c1 + y_c0 + y_c1)
        vectors.append(vector)
    if len(vectors) != 5:
        raise ValueError(f"expected 5 RFC 9380 G2 vectors, got {len(vectors)}")
    validate_messages([vector.message for vector in vectors], "G2")
    return dst, vectors


def parse_xmd(text: str) -> tuple[str, list[XmdVector], list[XmdVector]]:
    body = section(
        text,
        "K.1.  expand_message_xmd(SHA-256)",
        "K.2.  expand_message_xmd(SHA-256) (Long DST)",
    )
    dst = wrapped(body, "   DST     =", "\n   hash")
    by_length: dict[int, list[XmdVector]] = {32: [], 128: []}
    for block in body.split("\n   msg     =")[1:]:
        message = wrapped(block, "", "\n   len_in_bytes")
        length_text = wrapped(block, "   len_in_bytes =", "\n   DST_prime")
        try:
            length = int(length_text, 16)
        except ValueError as error:
            raise ValueError(f"invalid XMD output length {length_text}") from error
        output = hex_field(block, "   uniform_bytes =", "\n\n")
        if length not in by_length or len(output) != 2 * length:
            raise ValueError("invalid XMD output width")
        bytes.fromhex(output)
        by_length[length].append(XmdVector(message=message, output=output))
    for length, vectors in by_length.items():
        if len(vectors) != 5:
            raise ValueError(f"expected 5 RFC 9380 XMD-{length} vectors")
        validate_messages([vector.message for vector in vectors], f"XMD-{length}")
    return dst, by_length[32], by_length[128]


def rust_string(value: str, indent: str) -> str:
    chunks = [value[i : i + 64] for i in range(0, len(value), 64)] or [""]
    if len(chunks) == 1:
        return f'"{chunks[0]}"'
    lines = ["concat!("]
    lines.extend(f'{indent}    "{chunk}",' for chunk in chunks)
    lines.append(f"{indent})")
    return "\n".join(lines)


def rust_bytes(value: str, indent: str) -> str:
    if len(value) <= 64:
        return f'b"{value}"'
    return f"{rust_string(value, indent)}\n{indent}.as_bytes()"


def rust_hex(value: str, indent: str) -> str:
    chunks = [value[i : i + 64] for i in range(0, len(value), 64)]
    lines = ["commonware_formatting::hex!("]
    lines.append(f'{indent}    "0x{chunks[0]}"')
    lines.extend(f'{indent}    "{chunk}"' for chunk in chunks[1:])
    lines.append(f"{indent})")
    return "\n".join(lines)


def render(text: str) -> str:
    g1_dst, g1 = parse_g1(text)
    g2_dst, g2 = parse_g2(text)
    xmd_dst, xmd32, xmd128 = parse_xmd(text)
    if (g1_dst, g2_dst, xmd_dst) != (G1_DST, G2_DST, XMD_DST):
        raise ValueError("unexpected RFC 9380 domain separation tag")
    messages = [vector.message for vector in g1]
    for suite in (g2, xmd32, xmd128):
        if [vector.message for vector in suite] != messages:
            raise ValueError("RFC 9380 suites use different messages")
    lines = [
        "// Generated by cryptography/bls/generate_test_vectors.py.",
        "// Do not edit manually.",
        "//",
        f"// RFC 9380: {RFC9380_URL}",
        "",
        f'pub(crate) const RFC9380_G1_DST: &[u8] = b"{g1_dst}";',
        f'pub(crate) const RFC9380_G2_DST: &[u8] = b"{g2_dst}";',
        f'pub(crate) const RFC9380_XMD_SHA256_DST: &[u8] = b"{xmd_dst}";',
        "",
        "pub(crate) struct G1Vector {",
        "    pub(crate) message: &'static [u8],",
        "    pub(crate) x: [u8; 48],",
        "    pub(crate) y: [u8; 48],",
        "}",
        "",
        "pub(crate) const RFC9380_G1_RO: &[G1Vector] = &[",
    ]
    for vector in g1:
        lines.extend(
            [
                "    G1Vector {",
                f"        message: {rust_bytes(vector.message, '        ')},",
                f"        x: {rust_hex(vector.x, '        ')},",
                f"        y: {rust_hex(vector.y, '        ')},",
                "    },",
            ]
        )
    lines.extend(
        [
            "];",
            "",
        "pub(crate) struct G2Vector {",
        "    pub(crate) message: &'static [u8],",
        "    pub(crate) x_c0: [u8; 48],",
        "    pub(crate) x_c1: [u8; 48],",
        "    pub(crate) y_c0: [u8; 48],",
        "    pub(crate) y_c1: [u8; 48],",
            "}",
            "",
            "pub(crate) const RFC9380_G2_RO: &[G2Vector] = &[",
        ]
    )
    for vector in g2:
        lines.extend(
            [
                "    G2Vector {",
                f"        message: {rust_bytes(vector.message, '        ')},",
                f"        x_c0: {rust_hex(vector.x_c0, '        ')},",
                f"        x_c1: {rust_hex(vector.x_c1, '        ')},",
                f"        y_c0: {rust_hex(vector.y_c0, '        ')},",
                f"        y_c1: {rust_hex(vector.y_c1, '        ')},",
                "    },",
            ]
        )
    lines.extend(
        [
            "];",
            "",
            "pub(crate) struct XmdVector<const N: usize> {",
            "    pub(crate) message: &'static [u8],",
            "    pub(crate) output: [u8; N],",
            "}",
        ]
    )
    for name, length, vectors in (
        ("RFC9380_XMD_SHA256_32", 32, xmd32),
        ("RFC9380_XMD_SHA256_128", 128, xmd128),
    ):
        lines.extend(["", f"pub(crate) const {name}: &[XmdVector<{length}>] = &["])
        for vector in vectors:
            lines.extend(
                [
                    "    XmdVector {",
                    f"        message: {rust_bytes(vector.message, '        ')},",
                    f"        output: {rust_hex(vector.output, '        ')},",
                    "    },",
                ]
            )
        lines.append("];")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail if the checked-in vectors differ from regenerated output",
    )
    args = parser.parse_args()
    generated = render(strip_page_headers(fetch()))

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
