// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.15;

import { Test } from "forge-std/Test.sol";
import { LibSimplex as Simplex } from "../src/simplex/LibSimplex.sol";

/// @dev External calls exercise ABI boundaries and memory ownership around library calls.
contract SimplexHarness is Test {
    /// @dev Verify compact signature bytes against a padded key and a framed message.
    function verify(bool minSig, bytes calldata signature, bytes memory key, bytes memory message)
        external
        view
        returns (bool)
    {
        return minSig
            ? Simplex.verifyMinSig(signature, abi.decode(key, (Simplex.G2Point)), message)
            : Simplex.verifyMinPk(signature, abi.decode(key, (Simplex.G1Point)), message);
    }

    /// @dev Encode a hash point in the same padded format as the reference generator.
    function hash(bool minSig, bytes memory message) public view returns (bytes memory) {
        return minSig ? abi.encode(Simplex.hashToG1(message)) : abi.encode(Simplex.hashToG2(message));
    }

    /// @dev Exercise hashing after dirty scratch, then allocate and hash again.
    function checkedHash(bool minSig, bytes memory message) external view returns (bytes memory point) {
        bytes32 beforeInput = keccak256(message);
        uint256 beforeFree;
        assembly ("memory-safe") {
            beforeFree := mload(0x40)
            mstore(0, not(0))
            mstore(0x20, not(0))
            for { let p := beforeFree } lt(p, add(beforeFree, 0x1000)) { p := add(p, 0x20) } { mstore(p, not(0)) }
        }
        point = hash(minSig, message);
        uint256 afterFree;
        uint256 zero;
        assembly ("memory-safe") {
            afterFree := mload(0x40)
            zero := mload(0x60)
        }
        assertGe(afterFree, beforeFree, "free pointer moved backwards");
        assertEq(afterFree & 31, 0, "unaligned free pointer");
        assertEq(zero, 0, "dirty zero slot");
        assertEq(keccak256(message), beforeInput, "message changed");
        bytes memory fresh = new bytes(257);
        for (uint256 i = 0; i < fresh.length; ++i) {
            assertEq(fresh[i], bytes1(0), "dirty fresh allocation");
        }
        bytes32 freshHash = keccak256(fresh);
        assertEq(hash(minSig, message), point, "hash changed after allocation");
        assertEq(keccak256(fresh), freshHash, "later call changed allocation");
        assertEq(keccak256(message), beforeInput, "later call changed message");
    }
}

contract LibSimplexTest is Test {
    struct Case {
        bytes signature;
        bytes key;
        bytes message;
        bytes point;
    }

    SimplexHarness internal harness;

    /// @dev Each test gets an independent external verifier harness.
    function setUp() public {
        harness = new SimplexHarness();
    }

    /// @dev Check the signing transcript against explicit varint and namespace bytes.
    function test_EncodeMessage() public pure {
        bytes32 payload = bytes32(uint256(42));
        assertEq(
            Simplex.encodeMessage(hex"0102", Simplex.Kind.Finalization, 128, 300, 127, payload),
            bytes.concat(hex"0b0102", bytes("_FINALIZE"), hex"8001ac027f", payload)
        );
        assertEq(
            Simplex.encodeMessage("", Simplex.Kind.Nullification, 0, type(uint64).max, 123, payload),
            bytes.concat(hex"08", bytes("_NULLIFY"), hex"00ffffffffffffffffff01")
        );
        bytes memory namespace = new bytes(119);
        bytes memory message = Simplex.encodeMessage(namespace, Simplex.Kind.Notarization, 0, 0, 0, payload);
        assertEq(message[0], bytes1(0x80));
        assertEq(message[1], bytes1(0x01));
    }

    /// @dev Signature size checks must reject truncated and extended encodings.
    function test_InvalidLengths() public view {
        bytes memory message = bytes("message");
        assertFalse(harness.verify(true, new bytes(95), new bytes(256), message));
        assertFalse(harness.verify(true, new bytes(97), new bytes(256), message));
        assertFalse(harness.verify(false, new bytes(191), new bytes(128), message));
        assertFalse(harness.verify(false, new bytes(193), new bytes(128), message));
    }

    /// @dev Pairing identity inputs cannot authenticate a message.
    function test_IdentityRejected() public view {
        assertFalse(harness.verify(true, new bytes(96), new bytes(256), bytes("message")));
        assertFalse(harness.verify(false, new bytes(192), new bytes(128), bytes("message")));
    }

    /// @dev Cover block boundaries and long messages with dirty scratch and later allocations.
    function test_MemorySafety() public view {
        uint256[8] memory lengths = [uint256(0), 1, 31, 32, 63, 64, 257, 1025];
        for (uint256 i = 0; i < lengths.length; ++i) {
            bytes memory message = new bytes(lengths[i]);
            for (uint256 j = 0; j < message.length; ++j) {
                message[j] = bytes1(uint8(j & 0xff));
            }
            harness.checkedHash(true, message);
            harness.checkedHash(false, message);
        }
    }

    /// @dev Match both hash-to-curve variants against Commonware for arbitrary bytes.
    function testFuzz_DifferentialHash(bool minSig, bytes memory message) public {
        string[] memory args = new string[](5);
        args[0] = _binary();
        args[1] = "simplex";
        args[2] = "hash";
        args[3] = minSig ? "minsig" : "minpk";
        args[4] = vm.toString(message);
        bytes memory expected = abi.decode(vm.ffi(args), (bytes));
        assertEq(harness.checkedHash(minSig, message), expected);
    }

    /// @dev Compare recovered signatures, framing, and wrong-message rejection with Commonware.
    function testFuzz_DifferentialCertificate(
        bool minSig,
        uint8 kind,
        bytes memory namespace,
        uint64 epoch,
        uint64 viewNumber,
        uint64 parent,
        bytes32 payload,
        uint64 seed
    ) public {
        Simplex.Kind vote = Simplex.Kind(kind % 3);
        Case memory c = _generate(minSig, vote, namespace, epoch, viewNumber, parent, payload, seed);
        bytes memory message = Simplex.encodeMessage(namespace, vote, epoch, viewNumber, parent, payload);
        assertEq(message, c.message, "signing transcript mismatch");
        assertEq(harness.hash(minSig, message), c.point, "hash point mismatch");
        _compare(minSig, c, true);
        c.message[c.message.length - 1] ^= bytes1(0x01);
        _compare(minSig, c, false);
    }

    /// @dev Exercise every vote domain and varint boundaries for both curve variants.
    function test_DifferentialDomains() public {
        for (uint256 family = 0; family != 2; ++family) {
            for (uint256 kind = 0; kind != 3; ++kind) {
                Simplex.Kind vote = Simplex.Kind(kind);
                Case memory c =
                    _generate(family == 0, vote, new bytes(119), type(uint64).max, 128, 127, bytes32(uint256(7)), 9);
                assertEq(
                    c.message,
                    Simplex.encodeMessage(new bytes(119), vote, type(uint64).max, 128, 127, bytes32(uint256(7)))
                );
                _compare(family == 0, c, true);
                c.message = Simplex.encodeMessage(
                    new bytes(119), Simplex.Kind((kind + 1) % 3), type(uint64).max, 128, 127, bytes32(uint256(7))
                );
                _compare(family == 0, c, false);
            }
        }
    }

    /// @dev Reject invalid lengths, coordinate encodings, and identities using bounded external calls.
    function test_DifferentialMalformedPoints() public {
        for (uint256 family = 0; family != 2; ++family) {
            bool minSig = family == 0;
            Case memory c =
                _generate(minSig, Simplex.Kind.Finalization, bytes("simplex"), 1, 300, 128, bytes32(uint256(7)), 9);
            _compare(minSig, c, true);
            bytes memory signature = c.signature;
            c.signature = new bytes(signature.length - 1);
            for (uint256 i = 0; i != c.signature.length; ++i) {
                c.signature[i] = signature[i];
            }
            _compare(minSig, c, false);
            c.signature = bytes.concat(signature, hex"00");
            _compare(minSig, c, false);
            c.signature = new bytes(signature.length);
            _compare(minSig, c, false);
            c.signature = bytes.concat(signature);
            c.signature[0] = 0xff;
            _compare(minSig, c, false);
            c.signature = signature;
            bytes memory key = c.key;
            c.key = new bytes(key.length);
            _compare(minSig, c, false);
            c.key = bytes.concat(key);
            c.key[0] = 0xff;
            _compare(minSig, c, false);
        }
    }

    /// @dev Measure each signature variant with a finalization message and trusted epoch key.
    function test_DifferentialGas() public {
        for (uint256 family = 0; family != 2; ++family) {
            bool minSig = family == 0;
            Case memory c =
                _generate(minSig, Simplex.Kind.Finalization, bytes("simplex"), 1, 300, 128, bytes32(uint256(7)), 9);
            assertTrue(harness.verify(minSig, c.signature, c.key, c.message));
            vm.snapshotGasLastFrame("Simplex", minSig ? "minsig" : "minpk");
        }
    }

    /// @dev Ask the generator for a signed subject and its independently encoded preimage.
    function _generate(
        bool minSig,
        Simplex.Kind kind,
        bytes memory namespace,
        uint64 epoch,
        uint64 viewNumber,
        uint64 parent,
        bytes32 payload,
        uint64 seed
    ) internal returns (Case memory c) {
        string[] memory args = new string[](11);
        args[0] = _binary();
        args[1] = "simplex";
        args[2] = "generate";
        args[3] = minSig ? "minsig" : "minpk";
        args[4] = kind == Simplex.Kind.Notarization
            ? "notarize"
            : kind == Simplex.Kind.Nullification ? "nullify" : "finalize";
        args[5] = vm.toString(namespace);
        args[6] = vm.toString(uint256(epoch));
        args[7] = vm.toString(uint256(viewNumber));
        args[8] = vm.toString(uint256(parent));
        args[9] = vm.toString(payload);
        args[10] = vm.toString(uint256(seed));
        (c.signature, c.key, c.message, c.point) = abi.decode(vm.ffi(args), (bytes, bytes, bytes, bytes));
    }

    /// @dev Compare rejection and acceptance without allowing invalid precompile inputs to consume all test gas.
    function _compare(bool minSig, Case memory c, bool expected) internal {
        string[] memory args = new string[](7);
        args[0] = _binary();
        args[1] = "simplex";
        args[2] = "check";
        args[3] = minSig ? "minsig" : "minpk";
        args[4] = vm.toString(c.key);
        args[5] = vm.toString(c.message);
        args[6] = vm.toString(c.signature);
        assertEq(abi.decode(vm.ffi(args), (bool)), expected, "Commonware result");
        (bool ok, bytes memory result) = address(harness).staticcall{ gas: 1_000_000 }(
            abi.encodeCall(harness.verify, (minSig, c.signature, c.key, c.message))
        );
        assertTrue(ok, "verifier reverted");
        assertEq(abi.decode(result, (bool)), expected, "Solidity result");
    }

    /// @dev Absolute FFI paths permit posix_spawn on macOS.
    function _binary() internal view returns (string memory) {
        return string.concat(vm.projectRoot(), "/../target/release/commonware-sol-fuzz");
    }
}
