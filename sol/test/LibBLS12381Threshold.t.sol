// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.15;

import { Test } from "forge-std/Test.sol";
import { LibBLS12381 as BLS } from "../src/certificate/LibBLS12381.sol";
import { LibBLS12381Threshold as Certificate } from "../src/certificate/LibBLS12381Threshold.sol";

/// @dev External calls exercise ABI boundaries and memory ownership around library calls.
contract CertificateHarness is Test {
    /// @dev Verify compact signature bytes against a padded key and a namespaced message.
    function verify(
        bool minSig,
        bytes calldata signature,
        bytes memory key,
        bytes memory namespace,
        bytes memory message
    ) external view returns (bool) {
        return minSig
            ? Certificate.verifyMinSig(signature, abi.decode(key, (BLS.G2Point)), namespace, message)
            : Certificate.verifyMinPk(signature, abi.decode(key, (BLS.G1Point)), namespace, message);
    }

    /// @dev Encode a hash point in the same padded format as the reference generator.
    function hash(bool minSig, bytes memory namespace, bytes memory message) public view returns (bytes memory) {
        return minSig ? abi.encode(BLS.hashToG1(namespace, message)) : abi.encode(BLS.hashToG2(namespace, message));
    }

    /// @dev Exercise hashing after dirty scratch, then allocate and hash again.
    function checkedHash(bool minSig, bytes memory namespace, bytes memory message)
        external
        view
        returns (bytes memory point)
    {
        bytes32 beforeInput = keccak256(abi.encode(namespace, message));
        uint256 beforeFree;
        assembly ("memory-safe") {
            beforeFree := mload(0x40)
            mstore(0, not(0))
            mstore(0x20, not(0))
            for { let p := beforeFree } lt(p, add(beforeFree, 0x1000)) { p := add(p, 0x20) } { mstore(p, not(0)) }
        }
        point = hash(minSig, namespace, message);
        uint256 afterFree;
        uint256 zero;
        assembly ("memory-safe") {
            afterFree := mload(0x40)
            zero := mload(0x60)
        }
        assertGe(afterFree, beforeFree, "free pointer moved backwards");
        assertEq(afterFree & 31, 0, "unaligned free pointer");
        assertEq(zero, 0, "dirty zero slot");
        assertEq(keccak256(abi.encode(namespace, message)), beforeInput, "inputs changed");
        bytes memory fresh = new bytes(257);
        for (uint256 i = 0; i < fresh.length; ++i) {
            assertEq(fresh[i], bytes1(0), "dirty fresh allocation");
        }
        bytes32 freshHash = keccak256(fresh);
        assertEq(hash(minSig, namespace, message), point, "hash changed after allocation");
        assertEq(keccak256(fresh), freshHash, "later call changed allocation");
        assertEq(keccak256(abi.encode(namespace, message)), beforeInput, "later call changed inputs");
    }
}

contract LibBLS12381ThresholdTest is Test {
    struct Case {
        bytes signature;
        bytes key;
        bytes message;
        bytes point;
    }

    CertificateHarness internal harness;

    function setUp() public {
        harness = new CertificateHarness();
    }

    function test_EncodeMessage() public pure {
        assertEq(BLS.encodeMessage("", ""), hex"00");
        assertEq(BLS.encodeMessage(hex"0102", hex"0304"), hex"0201020304");
        assertNotEq(BLS.encodeMessage("a", "bc"), BLS.encodeMessage("ab", "c"));
        assertEq(BLS.encodeMessage(new bytes(127), hex"01"), bytes.concat(hex"7f", new bytes(127), hex"01"));
        assertEq(BLS.encodeMessage(new bytes(128), hex"01"), bytes.concat(hex"8001", new bytes(128), hex"01"));
    }

    /// @dev Signature size checks must reject truncated and extended encodings.
    function test_InvalidLengths() public view {
        assertFalse(harness.verify(true, new bytes(95), new bytes(256), "", "message"));
        assertFalse(harness.verify(true, new bytes(97), new bytes(256), "", "message"));
        assertFalse(harness.verify(false, new bytes(191), new bytes(128), "", "message"));
        assertFalse(harness.verify(false, new bytes(193), new bytes(128), "", "message"));
    }

    /// @dev Pairing identity inputs cannot authenticate a message.
    function test_IdentityRejected() public view {
        assertFalse(harness.verify(true, new bytes(96), new bytes(256), "", "message"));
        assertFalse(harness.verify(false, new bytes(192), new bytes(128), "", "message"));
    }

    /// @dev Cover block boundaries and long inputs with dirty scratch and later allocations.
    function test_MemorySafety() public view {
        uint256[8] memory lengths = [uint256(0), 1, 31, 32, 63, 64, 257, 1025];
        for (uint256 i = 0; i < lengths.length; ++i) {
            bytes memory input = new bytes(lengths[i]);
            for (uint256 j = 0; j < input.length; ++j) {
                input[j] = bytes1(uint8(j & 0xff));
            }
            harness.checkedHash(true, input, input);
            harness.checkedHash(false, input, input);
        }
    }

    /// @dev Compare namespaced hash-to-curve points for arbitrary namespace/message boundaries.
    function testFuzz_DifferentialHash(bool minSig, bytes memory namespace, bytes memory message) public {
        string[] memory args = new string[](6);
        args[0] = _binary();
        args[1] = "certificate";
        args[2] = "hash";
        args[3] = minSig ? "minsig" : "minpk";
        args[4] = vm.toString(namespace);
        args[5] = vm.toString(message);
        bytes memory expected = abi.decode(vm.ffi(args), (bytes));
        assertEq(harness.checkedHash(minSig, namespace, message), expected);
    }

    /// @dev Recovered certificates bind the namespace and encoded subject independently.
    function testFuzz_DifferentialCertificate(bool minSig, bytes memory namespace, bytes memory message, uint64 seed)
        public
    {
        Case memory c = _generate(minSig, namespace, message, seed);
        assertEq(BLS.encodeMessage(namespace, message), c.message, "signing transcript mismatch");
        assertEq(harness.hash(minSig, namespace, message), c.point, "hash point mismatch");
        _compare(minSig, namespace, message, c, true);
        _compare(minSig, namespace, bytes.concat(message, hex"01"), c, false);
        _compare(minSig, bytes.concat(namespace, hex"01"), message, c, false);
    }

    function test_DifferentialNamespaceFraming() public {
        for (uint256 family; family != 2; ++family) {
            bool minSig = family == 0;
            Case memory c = _generate(minSig, "", "", 9);
            _compare(minSig, "", "", c, true);
            c = _generate(minSig, "a", "bc", 9);
            _compare(minSig, "a", "bc", c, true);
            _compare(minSig, "ab", "c", c, false);
        }
    }

    /// @dev Reject invalid lengths, coordinate encodings, and identities using bounded external calls.
    function test_DifferentialMalformedPoints() public {
        for (uint256 family = 0; family != 2; ++family) {
            bool minSig = family == 0;
            bytes memory namespace = bytes("certificate");
            bytes memory message = abi.encodePacked(bytes32(uint256(7)));
            Case memory c = _generate(minSig, namespace, message, 9);
            _compare(minSig, namespace, message, c, true);
            bytes memory signature = c.signature;
            c.signature = new bytes(signature.length - 1);
            for (uint256 i = 0; i != c.signature.length; ++i) {
                c.signature[i] = signature[i];
            }
            _compare(minSig, namespace, message, c, false);
            c.signature = bytes.concat(signature, hex"00");
            _compare(minSig, namespace, message, c, false);
            c.signature = new bytes(signature.length);
            _compare(minSig, namespace, message, c, false);
            c.signature = bytes.concat(signature);
            c.signature[0] = 0xff;
            _compare(minSig, namespace, message, c, false);
            c.signature = signature;
            bytes memory key = c.key;
            c.key = new bytes(key.length);
            _compare(minSig, namespace, message, c, false);
            c.key = bytes.concat(key);
            c.key[0] = 0xff;
            _compare(minSig, namespace, message, c, false);
        }
    }

    /// @dev Measure recovered certificate verification, including namespace framing.
    function test_DifferentialGas() public {
        bytes memory namespace = bytes("certificate");
        bytes memory message = abi.encodePacked(bytes32(uint256(7)));
        for (uint256 family; family != 2; ++family) {
            bool minSig = family == 0;
            Case memory c = _generate(minSig, namespace, message, 9);
            assertTrue(harness.verify(minSig, c.signature, c.key, namespace, message));
            vm.snapshotGasLastFrame("BLS12381Threshold", minSig ? "minsig" : "minpk");
        }
    }

    function _generate(bool minSig, bytes memory namespace, bytes memory message, uint64 seed)
        internal
        returns (Case memory c)
    {
        string[] memory args = new string[](7);
        args[0] = _binary();
        args[1] = "certificate";
        args[2] = "generate";
        args[3] = minSig ? "minsig" : "minpk";
        args[4] = vm.toString(namespace);
        args[5] = vm.toString(message);
        args[6] = vm.toString(uint256(seed));
        (c.signature, c.key, c.message, c.point) = abi.decode(vm.ffi(args), (bytes, bytes, bytes, bytes));
    }

    /// @dev Invalid precompile inputs get a bounded budget so every rejection case can complete.
    function _compare(bool minSig, bytes memory namespace, bytes memory message, Case memory c, bool expected)
        internal
    {
        string[] memory args = new string[](8);
        args[0] = _binary();
        args[1] = "certificate";
        args[2] = "check";
        args[3] = minSig ? "minsig" : "minpk";
        args[4] = vm.toString(c.key);
        args[5] = vm.toString(namespace);
        args[6] = vm.toString(message);
        args[7] = vm.toString(c.signature);
        assertEq(abi.decode(vm.ffi(args), (bool)), expected, "Commonware result");
        (bool ok, bytes memory result) = address(harness).staticcall{ gas: 1_000_000 }(
            abi.encodeCall(harness.verify, (minSig, c.signature, c.key, namespace, message))
        );
        assertTrue(ok, "verifier reverted");
        assertEq(abi.decode(result, (bool)), expected, "Solidity result");
    }

    /// @dev Absolute FFI paths permit posix_spawn on macOS.
    function _binary() internal view returns (string memory) {
        return string.concat(vm.projectRoot(), "/../target/release/commonware-sol-fuzz");
    }
}
