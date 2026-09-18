// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.15;

// Hash-to-curve adapted from Solady and Ithaca.
// https://github.com/Vectorized/solady/blob/2afba69bf67b78dd4abeadcc696052b3a6f71499/src/utils/ext/ithaca/BLS.sol
//
// Copyright (c) 2022-2026 Solady.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

import { LibCodec } from "../codec/LibCodec.sol";

/// @notice Commonware BLS12-381 primitives backed by EIP-2537.
/// @dev Signatures use uncompressed coordinates; Rust certificate encodings must be converted first.
/// Public keys use EIP-2537 coordinates, with each field element padded to 64 bytes.
/// Hashing uses the Commonware BLS proof-of-possession ciphersuites.
/// Requires BLS precompiles on the execution chain.
library LibBLS12381 {
    /// @dev A G1 point with big-endian coordinates, each split into high and low words.
    struct G1Point {
        bytes32 xHi;
        bytes32 xLo;
        bytes32 yHi;
        bytes32 yLo;
    }

    /// @dev A G2 point with real component `c0` before imaginary component `c1`.
    /// Each big-endian coordinate component is split into high and low words.
    struct G2Point {
        bytes32 xC0Hi;
        bytes32 xC0Lo;
        bytes32 xC1Hi;
        bytes32 xC1Lo;
        bytes32 yC0Hi;
        bytes32 yC0Lo;
        bytes32 yC1Hi;
        bytes32 yC1Lo;
    }

    /// @dev A hash-to-curve precompile failed or returned an unexpected output length.
    error PrecompileFailed();

    /// @dev Commonware namespace lengths must fit in a `uint32`.
    error NamespaceTooLong();

    /// @notice Verify a MinSig signature over a namespaced message.
    /// @param signature Uncompressed G1 coordinates `x || y`, each 48 bytes without padding.
    /// @param publicKey The trusted G2 public key.
    /// @param namespace The signing namespace, without a length prefix.
    /// @param message The encoded subject, without namespace framing.
    /// @return valid Whether the signature is valid. Invalid lengths, points, and infinity return false.
    function verifyMinSig(
        bytes calldata signature,
        G2Point memory publicKey,
        bytes memory namespace,
        bytes memory message
    ) internal view returns (bool valid) {
        if (signature.length != 96) return false;
        G1Point memory sig;
        uint256 out;
        assembly ("memory-safe") { out := sig }
        _unpack(signature, out);
        return _pairing(abi.encode(sig, _negativeG2(), hashToG1(namespace, message), publicKey));
    }

    /// @notice Verify a MinPk signature over a namespaced message.
    /// @param signature Uncompressed G2 coordinates `x.c0 || x.c1 || y.c0 || y.c1`, each 48 bytes.
    /// @param publicKey The trusted G1 public key.
    /// @param namespace The signing namespace, without a length prefix.
    /// @param message The encoded subject, without namespace framing.
    /// @return valid Whether the signature is valid. Invalid lengths, points, and infinity return false.
    function verifyMinPk(
        bytes calldata signature,
        G1Point memory publicKey,
        bytes memory namespace,
        bytes memory message
    ) internal view returns (bool valid) {
        if (signature.length != 192) return false;
        G2Point memory sig;
        uint256 out;
        assembly ("memory-safe") { out := sig }
        _unpack(signature, out);
        return _pairing(abi.encode(_negativeG1(), sig, publicKey, hashToG2(namespace, message)));
    }

    /// @dev Add two G1 points. Invalid inputs or an unavailable precompile return false.
    /// EIP-2537 point addition does not check subgroup membership.
    function addG1(G1Point memory a, G1Point memory b) internal view returns (bool ok, G1Point memory result) {
        uint256 out;
        assembly ("memory-safe") { out := result }
        ok = _add(abi.encode(a, b), 0x0b, 0x80, out);
    }

    /// @dev Add two G2 points. Invalid inputs or an unavailable precompile return false.
    /// EIP-2537 point addition does not check subgroup membership.
    function addG2(G2Point memory a, G2Point memory b) internal view returns (bool ok, G2Point memory result) {
        uint256 out;
        assembly ("memory-safe") { out := result }
        ok = _add(abi.encode(a, b), 0x0d, 0x100, out);
    }

    /// @notice Hash a namespaced message to G1 with `BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_`.
    /// @dev The namespace is framed once with its varint length before the encoded subject.
    function hashToG1(bytes memory namespace, bytes memory message) internal view returns (G1Point memory result) {
        uint256 out;
        assembly ("memory-safe") { out := result }
        _hashToCurve(encodeMessage(namespace, message), out, false);
    }

    /// @notice Hash a namespaced message to G2 with `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`.
    /// @dev The namespace is framed once with its varint length before the encoded subject.
    function hashToG2(bytes memory namespace, bytes memory message) internal view returns (G2Point memory result) {
        uint256 out;
        assembly ("memory-safe") { out := result }
        _hashToCurve(encodeMessage(namespace, message), out, true);
    }

    /// @notice Frame a signing namespace and encoded subject as Commonware signed bytes.
    /// @dev The namespace length is encoded as a uint32 varint on every platform.
    function encodeMessage(bytes memory namespace, bytes memory message) internal pure returns (bytes memory) {
        // forge-lint: disable-next-line(require-revert-in-loop)
        if (namespace.length > type(uint32).max) revert NamespaceTooLong();
        // forge-lint: disable-next-line(unsafe-typecast)
        return bytes.concat(LibCodec.encodeVarint(uint64(namespace.length)), namespace, message);
    }

    /// @dev Pad each 48-byte coordinate component into an allocated 64-byte precompile field.
    function _unpack(bytes calldata signature, uint256 out) private pure {
        assembly ("memory-safe") {
            for { let i := 0 } lt(i, signature.length) { i := add(i, 48) } {
                mstore(out, shr(128, calldataload(add(signature.offset, i))))
                mstore(add(out, 32), calldataload(add(add(signature.offset, i), 16)))
                out := add(out, 64)
            }
        }
    }

    /// @dev Call a point-add precompile with distinct input and output allocations.
    function _add(bytes memory input, uint256 precompile, uint256 outputLength, uint256 out)
        private
        view
        returns (bool ok)
    {
        assembly ("memory-safe") {
            ok := staticcall(gas(), precompile, add(input, 0x20), mload(input), out, outputLength)
            ok := and(ok, eq(returndatasize(), outputLength))
        }
    }

    /// @dev Expand with SHA-256 XMD, reduce 64-byte limbs, map twice, and add.
    /// `out` points to an allocated G1 or G2 result.
    /// Temporary memory is confined to one assembly block and cleared before return.
    function _hashToCurve(bytes memory message, uint256 out, bool g2) private view {
        uint256 scratchLength = (0x100 + 0x40 + message.length + 0x60 + 31) & ~uint256(31);
        if (scratchLength < 0x300) scratchLength = 0x300;
        assembly ("memory-safe") {
            function fail() {
                mstore(0x00, 0x84e81692) // `PrecompileFailed()`.
                // A failed precompile cannot yield a valid hash point.
                // forge-lint: disable-next-line(require-revert-in-loop)
                revert(0x1c, 0x04)
            }
            function dstPrime(o, counter, isG2) -> end {
                mstore8(o, counter)
                switch isG2
                case 0 { mstore(add(o, 1), "BLS_SIG_BLS12381G1_XMD:SHA-256_S") }
                default { mstore(add(o, 1), "BLS_SIG_BLS12381G2_XMD:SHA-256_S") }
                mstore(add(o, 0x21), "SWU_RO_POP_\x2b")
                end := add(o, 0x2d)
            }
            function sha2(data, length) -> digest {
                let ok := staticcall(gas(), 2, data, length, 0, 0x20)
                if iszero(and(ok, eq(returndatasize(), 0x20))) { fail() }
                digest := mload(0)
            }
            let b := mload(0x40)
            let end := add(b, scratchLength)
            let s := add(b, 0x100)
            mstore(s, 0)
            mstore(add(s, 0x20), 0)
            for { let i := 0 } lt(i, mload(message)) { i := add(i, 0x20) } {
                mstore(add(add(s, 0x40), i), mload(add(add(message, 0x20), i)))
            }
            let uniformLength := shl(add(7, g2), 1)
            let o := add(add(s, 0x40), mload(message))
            mstore(o, shl(240, uniformLength))
            let b0 := sha2(s, sub(dstPrime(add(o, 2), 0, g2), s))
            mstore(s, b0)
            mstore(b, sha2(s, sub(dstPrime(add(s, 0x20), 1, g2), s)))
            for { let i := 1 } lt(i, shr(5, uniformLength)) { i := add(i, 1) } {
                mstore(s, xor(b0, mload(add(b, shl(5, sub(i, 1))))))
                mstore(add(b, shl(5, i)), sha2(s, sub(dstPrime(add(s, 0x20), add(i, 1), g2), s)))
            }
            // Modexp with exponent one reduces each 64-byte hash limb modulo the base field.
            mstore(s, 0x40)
            mstore(add(s, 0x20), 0x20)
            mstore(add(s, 0x40), 0x40)
            mstore(add(s, 0xa0), 1)
            mstore(add(s, 0xc0), 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
            mstore(add(s, 0xe0), 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
            for { let i := 0 } lt(i, uniformLength) { i := add(i, 0x40) } {
                mstore(add(s, 0x60), mload(add(b, i)))
                mstore(add(s, 0x80), mload(add(add(b, i), 0x20)))
                let ok := staticcall(gas(), 5, s, 0x100, add(b, i), 0x40)
                if iszero(and(ok, eq(returndatasize(), 0x40))) { fail() }
            }
            let fieldSize := shl(add(6, g2), 1)
            let pointSize := shl(1, fieldSize)
            let mapAddress := add(0x10, g2)
            let ok := staticcall(gas(), mapAddress, b, fieldSize, s, pointSize)
            if iszero(and(ok, eq(returndatasize(), pointSize))) { fail() }
            ok := staticcall(gas(), mapAddress, add(b, fieldSize), fieldSize, add(s, pointSize), pointSize)
            if iszero(and(ok, eq(returndatasize(), pointSize))) { fail() }
            ok := staticcall(gas(), add(0x0b, shl(1, g2)), s, shl(1, pointSize), out, pointSize)
            if iszero(and(ok, eq(returndatasize(), pointSize))) { fail() }
            for { let p := b } lt(p, end) { p := add(p, 0x20) } { mstore(p, 0) }
        }
    }

    /// @dev Check two pairing terms, rejecting infinity in every input point.
    /// The pairing precompile enforces canonical coordinates, curve membership, and subgroup membership.
    function _pairing(bytes memory input) private view returns (bool valid) {
        assembly ("memory-safe") {
            let data := add(input, 0x20)
            let nonzero := 1
            for { let p := data } lt(p, add(data, 0x300)) { p := add(p, 0x180) } {
                let g1 := 0
                let g2 := 0
                for { let i := 0 } lt(i, 0x80) { i := add(i, 0x20) } { g1 := or(g1, mload(add(p, i))) }
                for { let i := 0x80 } lt(i, 0x180) { i := add(i, 0x20) } { g2 := or(g2, mload(add(p, i))) }
                nonzero := and(nonzero, and(iszero(iszero(g1)), iszero(iszero(g2))))
            }
            if nonzero {
                let ok := staticcall(gas(), 0x0f, data, 0x300, 0, 0x20)
                valid := and(and(ok, eq(returndatasize(), 0x20)), eq(mload(0), 1))
            }
        }
    }

    /// @dev The negated standard BLS12-381 G1 generator in precompile encoding.
    function _negativeG1() private pure returns (G1Point memory) {
        return G1Point(
            0x0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0f,
            0xc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb,
            0x00000000000000000000000000000000114d1d6855d545a8aa7d76c8cf2e21f2,
            0x67816aef1db507c96655b9d5caac42364e6f38ba0ecb751bad54dcd6b939c2ca
        );
    }

    /// @dev The negated standard BLS12-381 G2 generator in precompile encoding.
    function _negativeG2() private pure returns (G2Point memory) {
        return G2Point(
            0x00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051,
            0xc6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8,
            0x0000000000000000000000000000000013e02b6052719f607dacd3a088274f65,
            0x596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e,
            0x000000000000000000000000000000000d1b3cc2c7027888be51d9ef691d77bc,
            0xb679afda66c73f17f9ee3837a55024f78c71363275a75d75d86bab79f74782aa,
            0x0000000000000000000000000000000013fa4d4a0ad8b1ce186ed5061789213d,
            0x993923066dddaf1040bc3ff59f825c78df74f2d75467e25e0f55f8a00fa030ed
        );
    }
}
