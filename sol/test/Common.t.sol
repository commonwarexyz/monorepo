// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.15;

import { Test } from "forge-std/Test.sol";
import { Common } from "../src/merkle/Common.sol";
import { LibBMT } from "../src/merkle/LibBMT.sol";
import { LibMMR } from "../src/merkle/LibMMR.sol";
import { LibMMB } from "../src/merkle/LibMMB.sol";
import { LibMerkle } from "../src/merkle/LibMerkle.sol";

/// @dev Virtual constants specialize verifier callers without a runtime hasher parameter.
abstract contract HashSelection {
    /// @dev Select native Keccak hashing.
    function _hasher() internal pure virtual returns (address) {
        return address(0);
    }

    /// @dev Build reference digests independently of the verifier's hashing implementation.
    function _hash(bytes memory input) internal pure returns (bytes32) {
        return _hasher() == address(0) ? keccak256(input) : sha256(input);
    }
}

abstract contract HashTest is Test, HashSelection {
    /// @dev Ask the Rust oracle to use the same hash algorithm as the verifier.
    function _ffi(string[] memory args) internal returns (bytes memory) {
        string[] memory selected = new string[](args.length + 2);
        // QMDB selects its hash per operation. BMT and Merkle select it at the family command.
        uint256 hashIndex = keccak256(bytes(args[1])) == keccak256("qmdb") ? args.length : 2;
        for (uint256 i; i < args.length; ++i) {
            selected[i < hashIndex ? i : i + 2] = args[i];
        }
        selected[hashIndex] = "--hash";
        selected[hashIndex + 1] = _hasher() == address(0) ? "keccak" : "sha256";
        return vm.ffi(selected);
    }

    /// @dev Keep gas snapshots for distinct hashing algorithms in separate groups.
    function _group(string memory family) internal pure returns (string memory) {
        return _hasher() == address(0) ? family : string.concat(family, "Sha256");
    }
}

struct CompatibilityCase {
    bytes32 root;
    uint256 leaves;
    uint256 start;
    uint256 inactive;
    bool belt;
    bool backward;
    uint8 mode;
    uint256[] indices;
    uint256[] positions;
    bytes32[] elements;
    bytes32[] proof;
}

/// @dev Exercises policy-aware memory and calldata entrypoints with caller-owned inputs and reusable scratch.
abstract contract CompatibilityHarness is HashTest {
    function memoryVerify(
        CompatibilityCase calldata c,
        uint256[] memory indices,
        uint256[] memory positions,
        bytes32[] memory elements,
        bytes32[] memory proof
    ) internal view returns (bool) {
        if (c.mode == 2) {
            return c.belt
                ? LibMMB.verifyMulti(
                    c.root,
                    c.leaves,
                    indices,
                    elements,
                    positions,
                    proof,
                    c.backward ? LibMerkle.Bagging.BackwardFold : LibMerkle.Bagging.ForwardFold,
                    c.inactive,
                    _hasher()
                )
                : LibMMR.verifyMulti(
                    c.root,
                    c.leaves,
                    indices,
                    elements,
                    positions,
                    proof,
                    c.backward ? LibMerkle.Bagging.BackwardFold : LibMerkle.Bagging.ForwardFold,
                    c.inactive,
                    _hasher()
                );
        }
        if (c.mode == 1) {
            return c.belt
                ? LibMMB.verify(
                    c.root,
                    c.leaves,
                    c.start,
                    elements[0],
                    proof,
                    c.backward ? LibMerkle.Bagging.BackwardFold : LibMerkle.Bagging.ForwardFold,
                    c.inactive,
                    _hasher()
                )
                : LibMMR.verify(
                    c.root,
                    c.leaves,
                    c.start,
                    elements[0],
                    proof,
                    c.backward ? LibMerkle.Bagging.BackwardFold : LibMerkle.Bagging.ForwardFold,
                    c.inactive,
                    _hasher()
                );
        }
        return c.belt
            ? LibMMB.verifyRange(
                c.root,
                c.leaves,
                c.start,
                elements,
                proof,
                c.backward ? LibMerkle.Bagging.BackwardFold : LibMerkle.Bagging.ForwardFold,
                c.inactive,
                _hasher()
            )
            : LibMMR.verifyRange(
                c.root,
                c.leaves,
                c.start,
                elements,
                proof,
                c.backward ? LibMerkle.Bagging.BackwardFold : LibMerkle.Bagging.ForwardFold,
                c.inactive,
                _hasher()
            );
    }

    function calldataVerify(
        CompatibilityCase calldata c,
        uint256[] calldata indices,
        uint256[] calldata positions,
        bytes32[] calldata elements,
        bytes32[] calldata proof
    ) internal view returns (bool) {
        if (c.mode == 2) {
            return c.belt
                ? LibMMB.verifyMultiCalldata(
                    c.root,
                    c.leaves,
                    indices,
                    elements,
                    positions,
                    proof,
                    c.backward ? LibMerkle.Bagging.BackwardFold : LibMerkle.Bagging.ForwardFold,
                    c.inactive,
                    _hasher()
                )
                : LibMMR.verifyMultiCalldata(
                    c.root,
                    c.leaves,
                    indices,
                    elements,
                    positions,
                    proof,
                    c.backward ? LibMerkle.Bagging.BackwardFold : LibMerkle.Bagging.ForwardFold,
                    c.inactive,
                    _hasher()
                );
        }
        if (c.mode == 1) {
            return c.belt
                ? LibMMB.verifyCalldata(
                    c.root,
                    c.leaves,
                    c.start,
                    elements[0],
                    proof,
                    c.backward ? LibMerkle.Bagging.BackwardFold : LibMerkle.Bagging.ForwardFold,
                    c.inactive,
                    _hasher()
                )
                : LibMMR.verifyCalldata(
                    c.root,
                    c.leaves,
                    c.start,
                    elements[0],
                    proof,
                    c.backward ? LibMerkle.Bagging.BackwardFold : LibMerkle.Bagging.ForwardFold,
                    c.inactive,
                    _hasher()
                );
        }
        return c.belt
            ? LibMMB.verifyRangeCalldata(
                c.root,
                c.leaves,
                c.start,
                elements,
                proof,
                c.backward ? LibMerkle.Bagging.BackwardFold : LibMerkle.Bagging.ForwardFold,
                c.inactive,
                _hasher()
            )
            : LibMMR.verifyRangeCalldata(
                c.root,
                c.leaves,
                c.start,
                elements,
                proof,
                c.backward ? LibMerkle.Bagging.BackwardFold : LibMerkle.Bagging.ForwardFold,
                c.inactive,
                _hasher()
            );
    }

    function verify(CompatibilityCase calldata c, bool direct, bool sliced) external view returns (bool) {
        uint256[] calldata indices = c.indices;
        uint256[] calldata positions = c.positions;
        bytes32[] calldata elements = c.elements;
        bytes32[] calldata proof = c.proof;
        if (sliced) {
            indices = indices[1:indices.length - 1];
            positions = positions[1:positions.length - 1];
            elements = elements[1:elements.length - 1];
            proof = proof[1:proof.length - 1];
        }
        return direct
            ? calldataVerify(c, indices, positions, elements, proof)
            : memoryVerify(c, indices, positions, elements, proof);
    }

    function checked(CompatibilityCase calldata c, bool direct) external view returns (bool valid) {
        CompatibilityCase memory inputs = c;
        bytes memory allocated = new bytes(97);
        for (uint256 i; i < allocated.length; ++i) {
            allocated[i] = bytes1(uint8(i + 1));
        }
        bytes32 beforeInputs =
            keccak256(abi.encode(inputs.indices, inputs.positions, inputs.elements, inputs.proof, allocated));
        uint256 beforePointer;
        uint256 scratchEnd;
        uint256 pointerChanged;
        uint256 zeroChanged;
        uint256 dirty;
        bool repeated = true;
        // The reserved region covers copied elements, peak buffers and the deepest supported DFS.
        uint256 scratchBytes = 0x4000 + inputs.proof.length * 32 + inputs.elements.length * 64;
        assembly ("memory-safe") {
            beforePointer := mload(0x40)
            scratchEnd := add(beforePointer, scratchBytes)
            for { let p := beforePointer } lt(p, scratchEnd) { p := add(p, 0x20) } { mstore(p, not(0)) }
        }
        // No allocation occurs between calls so every invocation reuses the same scratch region.
        // The first result checks independence from dirty scratch. Later calls also check cleanup.
        for (uint256 repeat; repeat < 3; ++repeat) {
            bool result = direct
                ? calldataVerify(c, c.indices, c.positions, c.elements, c.proof)
                : memoryVerify(c, inputs.indices, inputs.positions, inputs.elements, inputs.proof);
            assembly ("memory-safe") {
                pointerChanged := or(pointerChanged, xor(mload(0x40), beforePointer))
                zeroChanged := or(zeroChanged, mload(0x60))
                for { let p := beforePointer } lt(p, scratchEnd) { p := add(p, 0x20) } {
                    switch repeat
                    case 0 { mstore(p, 0) }
                    default { dirty := or(dirty, mload(p)) }
                }
            }
            if (repeat != 0 && result != valid) repeated = false;
            valid = result;
        }
        bytes memory fresh = new bytes(97);
        bool initialized = true;
        for (uint256 i; i < fresh.length; ++i) {
            if (fresh[i] != 0) initialized = false;
            fresh[i] = bytes1(uint8(i + 11));
        }
        assertEq(pointerChanged, 0, "free memory pointer changed");
        assertEq(zeroChanged, 0, "zero slot changed");
        assertEq(dirty, 0, "dirty verifier scratch");
        assertTrue(repeated, "repeated invocation changed result");
        assertTrue(initialized, "postcall allocation not zero initialized");
        assertEq(
            keccak256(abi.encode(inputs.indices, inputs.positions, inputs.elements, inputs.proof, allocated)),
            beforeInputs,
            "allocated input changed"
        );
        bytes32 freshHash = keccak256(fresh);
        bool later = direct
            ? calldataVerify(c, c.indices, c.positions, c.elements, c.proof)
            : memoryVerify(c, inputs.indices, inputs.positions, inputs.elements, inputs.proof);
        assertEq(later, valid, "verification after allocation changed result");
        assertEq(keccak256(fresh), freshHash, "later verification overwrote fresh allocation");
        assertEq(
            keccak256(abi.encode(inputs.indices, inputs.positions, inputs.elements, inputs.proof, allocated)),
            beforeInputs,
            "later verification overwrote input allocation"
        );
    }
}

/// @dev The reference builder simulates append/merge operations without using verifier geometry.
abstract contract VerifierHarness is HashTest {
    function referenceRoot(bytes32[] memory elements, bool belt) internal pure returns (bytes32) {
        bytes32[] memory peaks = new bytes32[](elements.length + 1);
        uint256[] memory heights = new uint256[](elements.length + 1);
        uint256 count;
        uint64 position;
        for (uint256 i; i < elements.length; ++i) {
            peaks[count] = _hash(abi.encodePacked(position++, elements[i]));
            heights[count++] = 0;
            // Delayed merging chooses the newest equal-height pair first.
            for (uint256 j = count - 1; j > 0; --j) {
                if (heights[j - 1] != heights[j]) continue;
                peaks[j - 1] = _hash(abi.encodePacked(position++, peaks[j - 1], peaks[j]));
                ++heights[j - 1];
                for (uint256 k = j; k + 1 < count; ++k) {
                    peaks[k] = peaks[k + 1];
                    heights[k] = heights[k + 1];
                }
                --count;
                if (belt) break;
                j = count;
            }
        }
        if (count == 0) return _hash(abi.encodePacked(uint64(0)));
        bytes32 acc = peaks[0];
        for (uint256 i = 1; i < count; ++i) {
            acc = _hash(abi.encodePacked(acc, peaks[i]));
        }
        return _hash(abi.encodePacked(uint64(elements.length), acc));
    }

    function verifyRange(
        bool belt,
        bytes32 root,
        uint256 leaves,
        uint256 start,
        bytes32[] memory elements,
        bytes32[] memory proof
    ) public view returns (bool valid) {
        valid = belt
            ? LibMMB.verifyRange(root, leaves, start, elements, proof, _hasher())
            : LibMMR.verifyRange(root, leaves, start, elements, proof, _hasher());
        assertEq(valid, this.calldataRange(belt, root, leaves, start, elements, proof), "range calldata disagreement");
    }

    function verifySingle(
        bool belt,
        bytes32 root,
        uint256 leaves,
        uint256 index,
        bytes32 element,
        bytes32[] memory proof
    ) public view returns (bool valid) {
        valid = belt
            ? LibMMB.verify(root, leaves, index, element, proof, _hasher())
            : LibMMR.verify(root, leaves, index, element, proof, _hasher());
        assertEq(valid, this.calldataSingle(belt, root, leaves, index, element, proof), "single calldata disagreement");
    }

    function calldataRange(
        bool belt,
        bytes32 root,
        uint256 leaves,
        uint256 start,
        bytes32[] calldata elements,
        bytes32[] calldata proof
    ) external view returns (bool) {
        return belt
            ? LibMMB.verifyRangeCalldata(root, leaves, start, elements, proof, _hasher())
            : LibMMR.verifyRangeCalldata(root, leaves, start, elements, proof, _hasher());
    }

    function calldataSingle(
        bool belt,
        bytes32 root,
        uint256 leaves,
        uint256 index,
        bytes32 element,
        bytes32[] calldata proof
    ) external view returns (bool) {
        return belt
            ? LibMMB.verifyCalldata(root, leaves, index, element, proof, _hasher())
            : LibMMR.verifyCalldata(root, leaves, index, element, proof, _hasher());
    }

    function slicedCalldata(
        bool belt,
        bytes32 root,
        uint256 leaves,
        uint256 start,
        bytes32[] calldata elements,
        bytes32[] calldata proof,
        bool single
    ) external view returns (bool) {
        elements = elements[1:elements.length - 1];
        proof = proof[1:proof.length - 1];
        if (single) {
            return belt
                ? LibMMB.verifyCalldata(root, leaves, start, elements[0], proof, _hasher())
                : LibMMR.verifyCalldata(root, leaves, start, elements[0], proof, _hasher());
        }
        return belt
            ? LibMMB.verifyRangeCalldata(root, leaves, start, elements, proof, _hasher())
            : LibMMR.verifyRangeCalldata(root, leaves, start, elements, proof, _hasher());
    }

    function checkedVerification(
        bool belt,
        bytes32 root,
        uint256 leaves,
        uint256 start,
        bytes32[] memory elements,
        bytes32[] memory proof,
        bool single
    ) public returns (bool valid) {
        valid = this.checkedMemoryVerification(belt, root, leaves, start, elements, proof, single, false);
        assertEq(valid, this.checkedMemoryVerification(belt, root, leaves, start, elements, proof, single, true));
    }

    /// @dev Caller-owned arrays precede fresh DFS scratch. Inspect scratch before any subsequent allocation.
    function checkedMemoryVerification(
        bool belt,
        bytes32 root,
        uint256 leaves,
        uint256 start,
        bytes32[] calldata elements,
        bytes32[] calldata proof,
        bool single,
        bool calldataMode
    ) external returns (bool valid) {
        bytes32[] memory memoryElements = elements;
        bytes32[] memory memoryProof = proof;
        bytes32 beforeInputs = keccak256(abi.encode(memoryElements, memoryProof));
        uint256 beforePointer;
        uint256 inputsStart;
        assembly ("memory-safe") {
            beforePointer := mload(0x40)
            inputsStart := memoryElements
            if lt(memoryProof, inputsStart) { inputsStart := memoryProof }
        }
        vm.expectSafeMemory(uint64(beforePointer), uint64(beforePointer + 0x10000));
        // The IR compiler reserves spill slots before the decoded input arrays.
        vm.expectSafeMemory(0x60, uint64(inputsStart));
        assembly ("memory-safe") {
            beforePointer := mload(0x40)
            for { let p := beforePointer } lt(p, add(beforePointer, 0x2000)) { p := add(p, 0x20) } {
                mstore(p, 0)
            }
        }
        if (calldataMode) {
            if (single) {
                valid = belt
                    ? LibMMB.verifyCalldata(root, leaves, start, elements[0], proof, _hasher())
                    : LibMMR.verifyCalldata(root, leaves, start, elements[0], proof, _hasher());
            } else {
                valid = belt
                    ? LibMMB.verifyRangeCalldata(root, leaves, start, elements, proof, _hasher())
                    : LibMMR.verifyRangeCalldata(root, leaves, start, elements, proof, _hasher());
            }
        } else if (single) {
            valid = belt
                ? LibMMB.verify(root, leaves, start, memoryElements[0], memoryProof, _hasher())
                : LibMMR.verify(root, leaves, start, memoryElements[0], memoryProof, _hasher());
        } else {
            valid = belt
                ? LibMMB.verifyRange(root, leaves, start, memoryElements, memoryProof, _hasher())
                : LibMMR.verifyRange(root, leaves, start, memoryElements, memoryProof, _hasher());
        }
        uint256 afterPointer;
        uint256 zero;
        uint256 dirty;
        assembly ("memory-safe") {
            afterPointer := mload(0x40)
            zero := mload(0x60)
            for { let p := afterPointer } lt(p, add(beforePointer, 0x2000)) { p := add(p, 0x20) } {
                dirty := or(dirty, mload(p))
            }
        }
        vm.stopExpectSafeMemory();
        assertEq(zero, 0, "zero slot");
        assertEq(afterPointer, beforePointer, "free memory pointer");
        assertEq(afterPointer & 31, 0, "unaligned free memory pointer");
        assertEq(dirty, 0, "dirty DFS scratch");
        assertEq(keccak256(abi.encode(memoryElements, memoryProof)), beforeInputs, "input memory changed");
        assertEq(keccak256(abi.encode(elements, proof)), beforeInputs, "calldata changed");
        bytes memory allocated = new bytes(96);
        for (uint256 i; i < allocated.length; ++i) {
            assertEq(uint8(allocated[i]), 0);
            allocated[i] = bytes1(uint8(i + 1));
        }
        assertEq(
            valid,
            single
                ? verifySingle(belt, root, leaves, start, elements[0], memoryProof)
                : verifyRange(belt, root, leaves, start, memoryElements, memoryProof),
            "subsequent verification"
        );
        for (uint256 i; i < allocated.length; ++i) {
            assertEq(uint8(allocated[i]), i + 1, "subsequent call overwrote allocation");
        }
    }
}

/// @dev External calls isolate the verifier frame measured by gas snapshots.
interface IMerkleGasHarness {
    function verify(bytes32 root, uint256 leaves, uint256 index, bytes32 element, bytes32[] memory proof)
        external
        view
        returns (bool);

    function verifyRange(bytes32 root, uint256 leaves, uint256 start, bytes32[] memory elements, bytes32[] memory proof)
        external
        view
        returns (bool);

    function verifyCalldata(bytes32 root, uint256 leaves, uint256 index, bytes32 element, bytes32[] calldata proof)
        external
        view
        returns (bool);

    function verifyRangeCalldata(
        bytes32 root,
        uint256 leaves,
        uint256 start,
        bytes32[] calldata elements,
        bytes32[] calldata proof
    ) external view returns (bool);
}

/// @dev Shared scenarios receive a fixed family from each concrete test entrypoint.
/// FFI helpers require the differential profile and a release build of `commonware-sol-fuzz`.
/// Absolute executable paths let Rust use `posix_spawn` on macOS.
abstract contract MerkleTestCommon is VerifierHarness {
    struct Case {
        bytes32 root;
        bytes32[] elements;
        bytes32[] proof;
        uint256 leaves;
    }

    CompatibilityHarness internal harness;

    function checkCalldataSlices(bool belt, bytes32 a, bytes32 b) internal view {
        bytes32[] memory leaves = new bytes32[](2);
        leaves[0] = a;
        leaves[1] = b;
        bytes32 root = referenceRoot(leaves, belt);
        bytes32[] memory elements = new bytes32[](3);
        bytes32[] memory proof = new bytes32[](3);
        elements[0] = proof[0] = bytes32(type(uint256).max);
        elements[2] = proof[2] = bytes32(type(uint256).max - 1);
        elements[1] = a;
        proof[1] = _hash(abi.encodePacked(uint64(1), b));
        for (uint256 mode; mode < 2; ++mode) {
            assertTrue(this.slicedCalldata(belt, root, 2, 0, elements, proof, mode != 0));
            assertFalse(this.slicedCalldata(belt, root ^ bytes32(uint256(1)), 2, 0, elements, proof, mode != 0));
        }
    }

    function checkFullRange(bool belt, uint8 size, bytes32 seed) internal view {
        bytes32[] memory elements = new bytes32[](uint256(size) + 1);
        for (uint256 i; i < elements.length; ++i) {
            elements[i] = keccak256(abi.encode(seed, i));
        }
        bytes32 root = referenceRoot(elements, belt);
        bytes32[] memory proof = new bytes32[](0);
        assertTrue(verifyRange(belt, root, elements.length, 0, elements, proof));
        elements[size] ^= bytes32(uint256(1));
        assertFalse(verifyRange(belt, root, elements.length, 0, elements, proof));
    }

    function checkSingleLeaf(bool belt, bytes32 element) internal view {
        bytes32 root = _hash(abi.encodePacked(uint64(1), _hash(abi.encodePacked(uint64(0), element))));
        bytes32[] memory proof = new bytes32[](0);
        assertTrue(verifySingle(belt, root, 1, 0, element, proof));
        assertFalse(verifySingle(belt, root, 1, 1, element, proof));
        assertFalse(verifySingle(belt, root, 0, 0, element, proof));
        assertFalse(verifySingle(belt, root, 1, type(uint256).max, element, proof));
    }

    function checkTwoLeaves(bool belt, bytes32 a, bytes32 b) internal view {
        bytes32[] memory elements = new bytes32[](2);
        elements[0] = a;
        elements[1] = b;
        bytes32 root = referenceRoot(elements, belt);
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = _hash(abi.encodePacked(uint64(1), b));
        assertTrue(verifySingle(belt, root, 2, 0, a, proof));
        proof[0] = _hash(abi.encodePacked(uint64(0), a));
        assertTrue(verifySingle(belt, root, 2, 1, b, proof));
        proof[0] ^= bytes32(uint256(1));
        assertFalse(verifySingle(belt, root, 2, 1, b, proof));
    }

    function checkInvalidBounds(bool belt, uint256 leaves, uint256 start) internal view {
        bytes32[] memory elements = new bytes32[](1);
        bytes32[] memory proof = new bytes32[](0);
        uint256 maxLeaves = belt ? 0x400000000000001e : 0x4000000000000000;
        if (leaves > maxLeaves || start >= leaves) {
            assertFalse(verifyRange(belt, bytes32(0), leaves, start, elements, proof));
        }
        assertFalse(verifyRange(belt, bytes32(0), 1, type(uint256).max, elements, proof));
    }

    function checkEmptyTree(bool belt) internal view {
        bytes32[] memory empty = new bytes32[](0);
        bytes32 root = _hash(abi.encodePacked(uint64(0)));
        assertTrue(verifyRange(belt, root, 0, 0, empty, empty));
        assertFalse(verifyRange(belt, root, 1, 0, empty, empty));
    }

    function checkMemoryExitPaths(bool belt) internal {
        bytes32[] memory elements = new bytes32[](1);
        elements[0] = bytes32(uint256(42));
        bytes32[] memory empty = new bytes32[](0);
        bytes32 root = referenceRoot(elements, belt);
        for (uint256 mode; mode < 2; ++mode) {
            bool single = mode != 0;
            assertTrue(checkedVerification(belt, root, 1, 0, elements, empty, single));
            assertFalse(checkedVerification(belt, root ^ bytes32(uint256(1)), 1, 0, elements, empty, single));
            // A leftmost leaf is hashed before its missing right sibling is requested.
            assertFalse(checkedVerification(belt, bytes32(0), 2, 0, elements, empty, single));
            assertFalse(checkedVerification(belt, root, 1, 1, elements, empty, single));
            assertFalse(checkedVerification(belt, root, type(uint256).max, 0, elements, empty, single));
            assertFalse(checkedVerification(belt, root, 1, type(uint256).max, elements, empty, single));
        }
        assertTrue(checkedVerification(belt, _hash(abi.encodePacked(uint64(0))), 0, 0, empty, empty, false));
        assertFalse(checkedVerification(belt, root, 1, 0, empty, empty, false));
    }

    function checkMemorySafety(bool belt, uint8 n, bytes32 seed, bool malformed) internal {
        bytes32[] memory elements = new bytes32[](uint256(n) + 1);
        for (uint256 i; i < elements.length; ++i) {
            elements[i] = keccak256(abi.encode(seed, i));
        }
        bytes32 root = referenceRoot(elements, belt);
        bytes32[] memory proof = new bytes32[](malformed ? 1 : 0);
        assertEq(this.checkedVerification(belt, root, elements.length, 0, elements, proof, false), !malformed);
    }

    function generate(bool belt, uint256 leaves, uint256 start, uint256 length, uint64 seed, bool synthetic)
        internal
        returns (Case memory c)
    {
        string[] memory args = new string[](13);
        args[0] = string.concat(vm.projectRoot(), "/../target/release/commonware-sol-fuzz");
        args[1] = "merkle";
        args[2] = synthetic ? "synthetic" : "generate";
        args[3] = "--kind";
        args[4] = belt ? "mmb" : "mmr";
        args[5] = "--leaf-count";
        args[6] = vm.toString(leaves);
        args[7] = "--start";
        args[8] = vm.toString(start);
        args[9] = "--length";
        args[10] = vm.toString(length);
        args[11] = "--seed";
        args[12] = vm.toString(uint256(seed));
        (c.root, c.elements, c.proof, c.leaves) = abi.decode(_ffi(args), (bytes32, bytes32[], bytes32[], uint256));
        assertEq(c.leaves, leaves);
    }

    function rustCheck(bool belt, Case memory c, uint256 start) internal returns (bool) {
        string[] memory args = new string[](7);
        args[0] = string.concat(vm.projectRoot(), "/../target/release/commonware-sol-fuzz");
        args[1] = "merkle";
        args[2] = "check";
        args[3] = "--kind";
        args[4] = belt ? "mmb" : "mmr";
        args[5] = "--abi-hex";
        args[6] = vm.toString(abi.encode(c.root, c.leaves, start, c.elements, c.proof));
        return abi.decode(_ffi(args), (bool));
    }

    function compare(bool belt, Case memory c, uint256 start) internal returns (bool accepted) {
        accepted = verifyRange(belt, c.root, c.leaves, start, c.elements, c.proof);
        assertEq(accepted, rustCheck(belt, c, start), "Solidity / Commonware disagreement");
        if (c.elements.length == 1) {
            assertEq(accepted, verifySingle(belt, c.root, c.leaves, start, c.elements[0], c.proof));
        }
    }

    function exercise(bool belt, Case memory c, uint256 start, uint256 mutation) internal {
        assertTrue(compare(belt, c, start));
        assertTrue(this.checkedVerification(belt, c.root, c.leaves, start, c.elements, c.proof, false));
        if (c.elements.length == 1) {
            assertTrue(this.checkedVerification(belt, c.root, c.leaves, start, c.elements, c.proof, true));
        }
        assertFalse(compare(belt, c, start + 1));
        uint256 leaves = c.leaves;
        c.leaves ^= 1;
        assertFalse(compare(belt, c, start));
        c.leaves = leaves;
        bytes32 root = c.root;
        c.root ^= bytes32(uint256(1));
        assertFalse(compare(belt, c, start));
        assertFalse(this.checkedVerification(belt, c.root, c.leaves, start, c.elements, c.proof, false));
        if (c.elements.length == 1) {
            assertFalse(this.checkedVerification(belt, c.root, c.leaves, start, c.elements, c.proof, true));
        }
        c.root = root;
        if (c.elements.length != 0) {
            uint256 i = mutation % c.elements.length;
            c.elements[i] ^= bytes32(uint256(1));
            assertFalse(compare(belt, c, start));
            c.elements[i] ^= bytes32(uint256(1));
        }
        if (c.proof.length != 0) {
            uint256 i = mutation % c.proof.length;
            c.proof[i] ^= bytes32(uint256(1));
            assertFalse(compare(belt, c, start));
            c.proof[i] ^= bytes32(uint256(1));
            bytes32[] memory proof = c.proof;
            c.proof = new bytes32[](proof.length - 1);
            for (uint256 j; j < c.proof.length; ++j) {
                c.proof[j] = proof[j];
            }
            assertFalse(compare(belt, c, start));
            assertFalse(this.checkedVerification(belt, c.root, c.leaves, start, c.elements, c.proof, false));
            if (c.elements.length == 1) {
                assertFalse(this.checkedVerification(belt, c.root, c.leaves, start, c.elements, c.proof, true));
            }
            c.proof = proof;
        }
        bytes32[] memory extra = new bytes32[](c.proof.length + 1);
        for (uint256 i; i < c.proof.length; ++i) {
            extra[i] = c.proof[i];
        }
        c.proof = extra;
        assertFalse(compare(belt, c, start));
    }

    function checkDifferentialRange(bool belt, uint16 n, uint16 s, uint16 len, uint64 seed) internal {
        uint256 leaves = uint256(n) % 512 + 1;
        uint256 start = uint256(s) % leaves;
        uint256 length = uint256(len) % (leaves - start) + 1;
        exercise(belt, generate(belt, leaves, start, length, seed, false), start, seed);
    }

    function checkDifferentialIndividual(bool belt, uint16 n, uint16 s, uint64 seed) internal {
        uint256 leaves = uint256(n) % 1024 + 1;
        uint256 start = uint256(s) % leaves;
        exercise(belt, generate(belt, leaves, start, 1, seed, false), start, seed);
    }

    function checkDifferentialDeep(bool belt, uint8 exponent, uint64 offset, uint64 seed) internal {
        uint256 leaves = uint256(1) << (uint256(exponent) % 62 + 1);
        if (seed & 1 != 0) --leaves;
        uint256 start = uint256(offset) % leaves;
        uint256 length = leaves - start < 4 ? leaves - start : 4;
        exercise(belt, generate(belt, leaves, start, length, seed, true), start, seed);
    }

    function checkDifferentialPositionBitBoundaries(bool belt) internal {
        for (uint256 bit = 1; bit < 62; ++bit) {
            uint256 boundary = uint256(1) << bit;
            Case memory c = generate(belt, boundary + 1, boundary - 2, 3, 7, true);
            assertTrue(compare(belt, c, boundary - 2));
        }
    }

    function checkDifferentialMaximumSize(bool belt) internal {
        uint256 leaves = belt ? 0x400000000000001e : 0x4000000000000000;
        exercise(belt, generate(belt, leaves, 0, 1, 1, true), 0, 0);
        exercise(belt, generate(belt, leaves, leaves / 2 - 1, 4, 2, true), leaves / 2 - 1, 1);
        exercise(belt, generate(belt, leaves, leaves - 1, 1, 3, true), leaves - 1, 0);
    }

    function checkDifferentialMalformed(
        bool belt,
        uint64 leaves,
        uint64 start,
        bytes32 root,
        bytes32[] memory elements,
        bytes32[] memory proof
    ) internal {
        if (elements.length > 8) {
            assembly ("memory-safe") { mstore(elements, 8) }
        }
        if (proof.length > 16) {
            assembly ("memory-safe") { mstore(proof, 16) }
        }
        compare(belt, Case(root, elements, proof, leaves), start);
    }

    function checkDifferentialSmallRanges(bool belt) internal {
        for (uint256 leaves = 1; leaves <= 12; ++leaves) {
            for (uint256 start; start < leaves; ++start) {
                for (uint256 length = 1; length <= leaves - start; ++length) {
                    Case memory c = generate(belt, leaves, start, length, 7, false);
                    assertTrue(compare(belt, c, start));
                }
            }
        }
    }

    function checkDifferentialEmpty(bool belt) internal {
        bytes32[] memory empty = new bytes32[](0);
        Case memory c = Case(_hash(abi.encodePacked(uint64(0))), empty, empty, 0);
        assertTrue(compare(belt, c, 0));
        assertFalse(compare(belt, c, 1));
        c.leaves = 1;
        assertFalse(compare(belt, c, 0));
        c.leaves = 0;
        c.proof = new bytes32[](1);
        assertFalse(compare(belt, c, 0));
    }

    function checkDifferentialGas(bool belt, IMerkleGasHarness gasHarness) internal {
        Case memory c = generate(belt, 1024, 1023, 1, 7, false);
        bool valid = gasHarness.verify(c.root, c.leaves, 1023, c.elements[0], c.proof);
        vm.snapshotGasLastFrame(_group(belt ? "MMB" : "MMR"), "individual-1024-last");
        assertTrue(valid);
        valid = gasHarness.verifyCalldata(c.root, c.leaves, 1023, c.elements[0], c.proof);
        vm.snapshotGasLastFrame(_group(belt ? "MMB" : "MMR"), "individual-1024-last-calldata");
        assertTrue(valid);
        c = generate(belt, 1024, 480, 64, 7, false);
        valid = gasHarness.verifyRange(c.root, c.leaves, 480, c.elements, c.proof);
        vm.snapshotGasLastFrame(_group(belt ? "MMB" : "MMR"), "range-1024-middle-64");
        assertTrue(valid);
        valid = gasHarness.verifyRangeCalldata(c.root, c.leaves, 480, c.elements, c.proof);
        vm.snapshotGasLastFrame(_group(belt ? "MMB" : "MMR"), "range-1024-middle-64-calldata");
        assertTrue(valid);
    }

    function generate(CompatibilityCase memory c, uint256 length, uint64 seed, bool synthetic)
        internal
        returns (CompatibilityCase memory)
    {
        string[] memory args = new string[](17);
        args[0] = string.concat(vm.projectRoot(), "/../target/release/commonware-sol-fuzz");
        args[1] = "merkle";
        args[2] = synthetic ? "synthetic" : "generate";
        args[3] = "--kind";
        args[4] = c.belt ? "mmb" : "mmr";
        args[5] = "--leaf-count";
        args[6] = vm.toString(c.leaves);
        args[7] = "--start";
        args[8] = vm.toString(c.start);
        args[9] = "--length";
        args[10] = vm.toString(length);
        args[11] = "--seed";
        args[12] = vm.toString(uint256(seed));
        args[13] = "--bagging";
        args[14] = c.backward ? "backward" : "forward";
        args[15] = "--inactive-peaks";
        args[16] = vm.toString(c.inactive);
        (c.root, c.elements, c.proof, c.leaves) = abi.decode(_ffi(args), (bytes32, bytes32[], bytes32[], uint256));
        return c;
    }

    function generateMulti(CompatibilityCase memory c, uint64 seed, bool synthetic)
        internal
        returns (CompatibilityCase memory)
    {
        string memory locations = vm.toString(c.indices[0]);
        for (uint256 i = 1; i < c.indices.length; ++i) {
            locations = string.concat(locations, ",", vm.toString(c.indices[i]));
        }
        string[] memory args = new string[](15);
        args[0] = string.concat(vm.projectRoot(), "/../target/release/commonware-sol-fuzz");
        args[1] = "merkle";
        args[2] = synthetic ? "synthetic-multi" : "generate-multi";
        args[3] = "--kind";
        args[4] = c.belt ? "mmb" : "mmr";
        args[5] = "--leaf-count";
        args[6] = vm.toString(c.leaves);
        args[7] = "--locations";
        args[8] = locations;
        args[9] = "--seed";
        args[10] = vm.toString(uint256(seed));
        args[11] = "--bagging";
        args[12] = c.backward ? "backward" : "forward";
        args[13] = "--inactive-peaks";
        args[14] = vm.toString(c.inactive);
        (c.root, c.elements, c.proof, c.leaves, c.positions) =
            abi.decode(_ffi(args), (bytes32, bytes32[], bytes32[], uint256, uint256[]));
        c.mode = 2;
        return c;
    }

    function rustCheck(CompatibilityCase memory c) internal returns (bool) {
        string[] memory args = new string[](11);
        args[0] = string.concat(vm.projectRoot(), "/../target/release/commonware-sol-fuzz");
        args[1] = "merkle";
        args[2] = c.mode == 2 ? "check-multi" : "check";
        args[3] = "--kind";
        args[4] = c.belt ? "mmb" : "mmr";
        args[5] = "--abi-hex";
        args[6] = c.mode == 2
            ? vm.toString(abi.encode(c.root, c.leaves, c.indices, c.elements, c.proof, c.positions))
            : vm.toString(abi.encode(c.root, c.leaves, c.start, c.elements, c.proof));
        args[7] = "--bagging";
        args[8] = c.backward ? "backward" : "forward";
        args[9] = "--inactive-peaks";
        args[10] = vm.toString(c.inactive);
        return abi.decode(_ffi(args), (bool));
    }

    function compare(CompatibilityCase memory c, bool expected) internal {
        assertEq(rustCheck(c), expected, "Commonware expected result");
        assertEq(harness.checked(c, false), expected, "memory disagreement");
        assertEq(harness.checked(c, true), expected, "calldata disagreement");
    }

    function slices(CompatibilityCase memory c, bool expected) internal view {
        uint256[] memory indices = c.indices;
        uint256[] memory positions = c.positions;
        bytes32[] memory elements = c.elements;
        bytes32[] memory proof = c.proof;
        c.indices = new uint256[](indices.length + 2);
        c.positions = new uint256[](positions.length + 2);
        c.positions[0] = c.positions[positions.length + 1] = type(uint256).max;
        for (uint256 i; i < positions.length; ++i) {
            c.positions[i + 1] = positions[i];
        }
        c.elements = new bytes32[](elements.length + 2);
        c.proof = new bytes32[](proof.length + 2);
        c.indices[0] = c.indices[indices.length + 1] = type(uint256).max;
        c.elements[0] = c.elements[elements.length + 1] = bytes32(type(uint256).max);
        c.proof[0] = c.proof[proof.length + 1] = bytes32(type(uint256).max);
        for (uint256 i; i < indices.length; ++i) {
            c.indices[i + 1] = indices[i];
        }
        for (uint256 i; i < elements.length; ++i) {
            c.elements[i + 1] = elements[i];
        }
        for (uint256 i; i < proof.length; ++i) {
            c.proof[i + 1] = proof[i];
        }
        assertEq(harness.verify(c, true, true), expected, "sliced calldata disagreement");
        c.indices = indices;
        c.positions = positions;
        c.elements = elements;
        c.proof = proof;
    }

    function exercise(CompatibilityCase memory c) internal {
        compare(c, true);
        slices(c, true);
        c.root ^= bytes32(uint256(1));
        compare(c, false);
        slices(c, false);
        c.root ^= bytes32(uint256(1));
        c.inactive += 1;
        compare(c, false);
        c.inactive -= 1;
        c.leaves += 1;
        compare(c, false);
        c.leaves -= 1;
        if (c.elements.length != 0) {
            c.elements[0] ^= bytes32(uint256(1));
            compare(c, false);
            c.elements[0] ^= bytes32(uint256(1));
        }
        bytes32[] memory proof = c.proof;
        uint256[] memory positions = c.positions;
        if (proof.length != 0) {
            proof[proof.length - 1] ^= bytes32(uint256(1));
            compare(c, false);
            proof[proof.length - 1] ^= bytes32(uint256(1));
            c.proof = new bytes32[](proof.length - 1);
            for (uint256 i; i < c.proof.length; ++i) {
                c.proof[i] = proof[i];
            }
            if (c.mode == 2) {
                c.positions = new uint256[](positions.length - 1);
                for (uint256 i; i < c.positions.length; ++i) {
                    c.positions[i] = positions[i];
                }
            }
            compare(c, false);
        }
        c.proof = new bytes32[](proof.length + 1);
        for (uint256 i; i < proof.length; ++i) {
            c.proof[i] = proof[i];
        }
        if (c.mode == 2) {
            c.positions = new uint256[](positions.length + 1);
            for (uint256 i; i < positions.length; ++i) {
                c.positions[i] = positions[i];
            }
            c.positions[positions.length] = positions.length == 0 ? 0 : positions[positions.length - 1] + 1;
        }
        compare(c, false);
        c.proof = proof;
        c.positions = positions;
    }

    function peakWidths(bool belt, uint256 leaves) internal pure returns (uint256[] memory widths) {
        widths = new uint256[](leaves);
        uint256 count;
        for (uint256 leaf; leaf < leaves; ++leaf) {
            widths[count++] = 1;
            for (uint256 j = count - 1; j > 0; --j) {
                if (widths[j - 1] != widths[j]) continue;
                widths[j - 1] *= 2;
                for (uint256 k = j; k + 1 < count; ++k) {
                    widths[k] = widths[k + 1];
                }
                --count;
                if (belt) break;
                j = count;
            }
        }
        assembly ("memory-safe") { mstore(widths, count) }
    }

    function checkCompatibilityInactiveBoundaryMatrix(bool belt) internal {
        uint256[] memory widths = peakWidths(belt, 31);
        for (uint256 bagging; bagging < 2; ++bagging) {
            for (uint256 inactive; inactive <= widths.length; ++inactive) {
                CompatibilityCase memory c;
                c.belt = belt;
                c.backward = bagging != 0;
                c.leaves = 31;
                c.inactive = inactive;
                uint256 boundary;
                for (uint256 peak; peak < widths.length; ++peak) {
                    c.start = boundary;
                    c = generate(c, 1, 11, false);
                    c.mode = 1;
                    compare(c, true);
                    c.mode = 0;
                    compare(c, true);
                    boundary += widths[peak];
                    if (boundary < c.leaves) {
                        c.start = boundary - 1;
                        c = generate(c, 2, 11, false);
                        compare(c, true);
                        slices(c, true);
                    }
                }
            }
        }
    }

    function checkCompatibilityRangeMutations(bool belt) internal {
        for (uint256 bagging; bagging < 2; ++bagging) {
            CompatibilityCase memory c;
            c.belt = belt;
            c.backward = bagging != 0;
            c.leaves = 31;
            c.inactive = 2;
            c.start = 15;
            exercise(generate(c, 12, 7, false));
            c.start = 30;
            c.mode = 1;
            exercise(generate(c, 1, 7, false));
        }
    }

    function checkCompatibilityRange(bool belt, bool backward, uint8 n, uint8 s, uint8 len, uint8 inactive, uint64 seed)
        internal
    {
        CompatibilityCase memory c;
        c.belt = belt;
        c.backward = backward;
        c.leaves = uint256(n) % 64 + 1;
        c.start = uint256(s) % c.leaves;
        c.inactive = uint256(inactive) % (peakWidths(belt, c.leaves).length + 1);
        uint256 length = uint256(len) % (c.leaves - c.start) + 1;
        exercise(generate(c, length, seed, false));
    }

    function checkCompatibilityMaximumSize(bool belt) internal {
        for (uint256 bagging; bagging < 2; ++bagging) {
            CompatibilityCase memory c;
            c.belt = belt;
            c.backward = bagging != 0;
            c.leaves = c.belt ? 0x400000000000001e : 0x4000000000000000;
            c.inactive = 1;
            c.start = c.leaves / 2 - 1;
            exercise(generate(c, 4, 23, true));
            c.start = c.leaves - 1;
            c.mode = 1;
            exercise(generate(c, 1, 29, true));
        }
    }

    function checkCompatibilityDeep(bool belt, bool backward, uint8 exponent, uint64 offset, uint64 seed) internal {
        CompatibilityCase memory c;
        c.belt = belt;
        c.backward = backward;
        c.leaves = (uint256(1) << (uint256(exponent) % 61 + 2)) - 1;
        c.start = uint256(offset) % c.leaves;
        c.inactive = seed % 2;
        exercise(generate(c, c.leaves - c.start < 3 ? c.leaves - c.start : 3, seed, true));
    }

    function checkCompatibilityEmpty(bool belt) internal {
        for (uint256 bagging; bagging < 2; ++bagging) {
            for (uint8 mode; mode < 3; mode += 2) {
                CompatibilityCase memory c;
                c.belt = belt;
                c.backward = bagging != 0;
                c.mode = mode;
                c.root = _hash(abi.encodePacked(uint64(0)));
                compare(c, true);
                slices(c, true);
                c.inactive = 1;
                compare(c, false);
                c.inactive = 0;
                c.leaves = 1;
                compare(c, false);
            }
        }
    }

    function checkCompatibilitySparseMatrix(bool belt) internal {
        uint256 count = peakWidths(belt, 31).length;
        for (uint256 bagging; bagging < 2; ++bagging) {
            for (uint256 inactive; inactive <= count; ++inactive) {
                CompatibilityCase memory c;
                c.belt = belt;
                c.backward = bagging != 0;
                c.leaves = 31;
                c.inactive = inactive;
                c.indices = new uint256[](5);
                c.indices[0] = 30;
                c.indices[1] = 0;
                c.indices[2] = 16;
                c.indices[3] = 15;
                c.indices[4] = 16;
                exercise(generateMulti(c, 17, false));
            }
        }
    }

    function checkCompatibilitySparseWitnessOrdering(bool belt) internal {
        for (uint256 bagging; bagging < 2; ++bagging) {
            CompatibilityCase memory c;
            c.belt = belt;
            c.backward = bagging != 0;
            c.leaves = 31;
            c.inactive = 2;
            c.indices = new uint256[](3);
            c.indices[0] = 30;
            c.indices[1] = 3;
            c.indices[2] = 3;
            c = generateMulti(c, 9, false);
            compare(c, true);
            c.elements[2] ^= bytes32(uint256(1));
            compare(c, false);
            c.elements[2] ^= bytes32(uint256(1));
            (c.proof[0], c.proof[1]) = (c.proof[1], c.proof[0]);
            compare(c, false);
            (c.proof[0], c.proof[1]) = (c.proof[1], c.proof[0]);
            (c.positions[0], c.positions[1]) = (c.positions[1], c.positions[0]);
            compare(c, false);
            (c.positions[0], c.positions[1]) = (c.positions[1], c.positions[0]);
            (c.positions[0], c.positions[1]) = (c.positions[1], c.positions[0]);
            (c.proof[0], c.proof[1]) = (c.proof[1], c.proof[0]);
            compare(c, false);
            (c.positions[0], c.positions[1]) = (c.positions[1], c.positions[0]);
            (c.proof[0], c.proof[1]) = (c.proof[1], c.proof[0]);
            uint256 position = c.positions[1];
            c.positions[1] = c.positions[0];
            compare(c, false);
            c.positions[1] = position;
            c.positions[c.positions.length - 1] = type(uint256).max;
            compare(c, false);
            c = generateMulti(c, 9, false);
            uint256[] memory indices = c.indices;
            c.indices = new uint256[](2);
            c.indices[0] = indices[0];
            c.indices[1] = indices[1];
            compare(c, false);
            c.indices = indices;
            c.positions = new uint256[](0);
            compare(c, false);
        }
    }

    function checkCompatibilitySparse(bool belt, bool backward, uint8 n, uint64 seed) internal {
        CompatibilityCase memory c;
        c.belt = belt;
        c.backward = backward;
        c.leaves = uint256(n) % 64 + 1;
        c.inactive = uint256(seed) % (peakWidths(belt, c.leaves).length + 1);
        c.indices = new uint256[]((uint256(seed) >> 32) % 32 + 1);
        for (uint256 i; i < c.indices.length; ++i) {
            c.indices[i] = uint256(keccak256(abi.encode(seed, i))) % c.leaves;
        }
        exercise(generateMulti(c, seed, false));
    }

    function checkCompatibilitySparseMaximumSize(bool belt) internal {
        for (uint256 bagging; bagging < 2; ++bagging) {
            CompatibilityCase memory c;
            c.belt = belt;
            c.backward = bagging != 0;
            c.leaves = c.belt ? 0x400000000000001e : 0x4000000000000000;
            c.inactive = 1;
            c.indices = new uint256[](4);
            c.indices[0] = c.leaves - 1;
            c.indices[1] = 0;
            c.indices[2] = c.leaves / 2 - 1;
            c.indices[3] = c.leaves / 2;
            exercise(generateMulti(c, 31, true));
        }
    }

    function checkRootPolicyGas(bool belt) internal {
        for (uint256 bagging; bagging < 2; ++bagging) {
            CompatibilityCase memory c;
            c.belt = belt;
            c.backward = bagging != 0;
            c.leaves = 1023;
            c.start = 480;
            c.inactive = 2;
            c = generate(c, 64, 7, false);
            string memory group = string.concat(c.belt ? "MMB" : "MMR", "RootPolicy");
            string memory fold = c.backward ? "backward" : "forward";
            assertTrue(harness.verify(c, false, false));
            vm.snapshotGasLastFrame(_group(group), string.concat(fold, "-inactive-range-memory"));
            assertTrue(harness.verify(c, true, false));
            vm.snapshotGasLastFrame(_group(group), string.concat(fold, "-inactive-range-calldata"));
            c.indices = new uint256[](3);
            c.indices[0] = 0;
            c.indices[1] = 511;
            c.indices[2] = 1022;
            c = generateMulti(c, 7, false);
            assertTrue(harness.verify(c, false, false));
            vm.snapshotGasLastFrame(_group(group), string.concat(fold, "-inactive-sparse-memory"));
            assertTrue(harness.verify(c, true, false));
            vm.snapshotGasLastFrame(_group(group), string.concat(fold, "-inactive-sparse-calldata"));
        }
    }

    function checkCompatibilitySparseExactUnion(bool belt) internal {
        for (uint256 bagging; bagging < 2; ++bagging) {
            for (uint256 shape; shape < 5; ++shape) {
                CompatibilityCase memory c;
                c.belt = belt;
                c.backward = bagging != 0;
                c.leaves = 7;
                c.inactive = 1;
                c.indices = new uint256[](shape == 0 ? 7 : shape == 4 ? 4 : 2);
                if (shape == 0 || shape == 4) {
                    for (uint256 i; i < c.indices.length; ++i) {
                        c.indices[i] = i;
                    }
                } else {
                    c.indices[0] = 0;
                    c.indices[1] = shape == 1 ? 1 : shape == 2 ? 3 : 6;
                }
                c = generateMulti(c, 43, false);
                assertGt(c.proof.length, 0, "Rust union includes witnesses for supplied leaves");
                if (shape == 0) {
                    for (uint256 witness; witness < c.proof.length; ++witness) {
                        c.proof[witness] ^= bytes32(uint256(1));
                        compare(c, false);
                        c.proof[witness] ^= bytes32(uint256(1));
                    }
                }
                exercise(c);
                c.inactive = 0;
                compare(c, false);
            }
        }
    }

    function checkCompatibilityInvalidBounds(bool belt) internal {
        for (uint256 bagging; bagging < 2; ++bagging) {
            for (uint8 mode; mode < 3; ++mode) {
                CompatibilityCase memory c;
                c.belt = belt;
                c.backward = bagging != 0;
                c.mode = mode;
                c.leaves = 1;
                c.elements = new bytes32[](1);
                c.indices = new uint256[](1);
                c = mode == 2 ? generateMulti(c, 19, false) : generate(c, 1, 19, false);
                c.leaves = (c.belt ? 0x400000000000001e : 0x4000000000000000) + 1;
                compare(c, false);
                c.leaves = 1;
                c.start = type(uint256).max;
                c.indices[0] = type(uint256).max;
                compare(c, false);
            }
        }
    }

    function checkCompatibilityRootPolicyBinding(bool belt) internal {
        for (uint256 bagging; bagging < 2; ++bagging) {
            CompatibilityCase memory c;
            c.belt = belt;
            c.backward = bagging != 0;
            c.leaves = 31;
            c.start = 3;
            c = generate(c, 2, 41, false);
            bytes32 zeroBoundaryRoot = c.root;
            c.inactive = 1;
            c = generate(c, 2, 41, false);
            assertNotEq(c.root, zeroBoundaryRoot, "inactive boundary is root bound");
            compare(c, true);
            c.inactive = 0;
            compare(c, false);
            c.inactive = 1;
            c.backward = !c.backward;
            compare(c, false);
        }
    }
}

/// @dev Accept raw preimages and return exactly one SHA-256 digest without ABI framing.
contract RawSha256Hasher {
    /// @dev Hash the complete calldata, including its first four bytes.
    fallback(bytes calldata input) external returns (bytes memory) {
        return abi.encodePacked(sha256(input));
    }
}

/// @dev Supply malformed return data or a revert to exercise the hasher boundary.
contract InvalidHasher {
    uint256 internal immutable length;
    bool internal immutable fails;

    /// @dev Configure the raw response length and call outcome.
    constructor(uint256 responseLength, bool reverts) {
        length = responseLength;
        fails = reverts;
    }

    /// @dev Return raw bytes of the configured size, or revert.
    fallback(bytes calldata) external returns (bytes memory) {
        require(!fails);
        return new bytes(length);
    }
}

/// @dev A hasher cannot mutate storage when the verifier invokes it with STATICCALL.
contract WritingHasher {
    uint256 public writes;

    /// @dev Attempt a state change before returning a correctly sized digest.
    fallback(bytes calldata input) external returns (bytes memory) {
        ++writes;
        return abi.encodePacked(sha256(input));
    }
}

contract RawCompatibilityHarness is CompatibilityHarness {
    /// @dev Select the raw adapter installed by the test at a fixed non-precompile address.
    function _hasher() internal pure override returns (address) {
        return address(0x123400);
    }
}

/// @dev Test raw external hash targets through the same proof and memory contracts as precompiles.
contract HashAddressTest is MerkleTestCommon {
    /// @dev Select the fixed raw adapter address for verifier calls and SHA-256 reference roots.
    function _hasher() internal pure override returns (address) {
        return address(0x123400);
    }

    /// @dev Install a selector-free SHA-256 adapter and its compatibility harness.
    function setUp() public {
        vm.etch(_hasher(), address(new RawSha256Hasher()).code);
        harness = new RawCompatibilityHarness();
    }

    /// @dev Cover positioned leaf, parent, root and peak preimages with caller memory checks.
    function test_RawAdapterMemorySafety() public {
        for (uint256 family; family < 2; ++family) {
            checkMemoryExitPaths(family != 0);
            checkMemorySafety(family != 0, 30, bytes32(uint256(79)), false);
            checkMemorySafety(family != 0, 30, bytes32(uint256(79)), true);
        }
    }

    /// @dev Compare external hashing with Rust across both bagging policies and inactive peaks.
    function test_DifferentialRawAdapterPolicies() public {
        for (uint256 family; family < 2; ++family) {
            checkCompatibilityRange(family != 0, false, 30, 3, 9, 2, 71);
            checkCompatibilityRange(family != 0, true, 30, 3, 9, 2, 71);
            checkCompatibilitySparse(family != 0, false, 30, 71);
            checkCompatibilitySparse(family != 0, true, 30, 71);
        }
    }

    /// @dev Build a one-leaf proof shared by the three verification shapes.
    function singleCase(bool belt, bool bmt) internal pure returns (CompatibilityCase memory c) {
        c.belt = belt;
        c.leaves = 1;
        c.elements = new bytes32[](1);
        c.elements[0] = bytes32(uint256(42));
        c.indices = new uint256[](1);
        c.root = bmt
            ? sha256(abi.encodePacked(uint32(1), sha256(abi.encodePacked(uint32(0), c.elements[0]))))
            : sha256(abi.encodePacked(uint64(1), sha256(abi.encodePacked(uint64(0), c.elements[0]))));
    }

    /// @dev Exercise each BMT shape and input location against a raw hash address.
    function bmtVerify(CompatibilityCase calldata c, bool direct) external view returns (bool) {
        if (c.mode == 1) {
            return direct
                ? LibBMT.verifyCalldata(c.root, c.leaves, c.start, c.elements[0], c.proof, _hasher())
                : LibBMT.verify(c.root, c.leaves, c.start, c.elements[0], c.proof, _hasher());
        }
        if (c.mode == 2) {
            return direct
                ? LibBMT.verifyMultiCalldata(c.root, c.leaves, c.indices, c.elements, c.proof, _hasher())
                : LibBMT.verifyMulti(c.root, c.leaves, c.indices, c.elements, c.proof, _hasher());
        }
        return direct
            ? LibBMT.verifyRangeCalldata(c.root, c.leaves, c.start, c.elements, c.proof, _hasher())
            : LibBMT.verifyRange(c.root, c.leaves, c.start, c.elements, c.proof, _hasher());
    }

    /// @dev Raw adapters accept valid proofs. Using the other algorithm rejects the same root.
    function test_RawAdapterAndCrossHashRejection() public view {
        for (uint256 family; family < 3; ++family) {
            CompatibilityCase memory c = singleCase(family == 1, family == 2);
            for (uint8 mode; mode < 3; ++mode) {
                c.mode = mode;
                for (uint256 location; location < 2; ++location) {
                    assertTrue(family == 2 ? this.bmtVerify(c, location != 0) : harness.checked(c, location != 0));
                }
            }
            bytes32[] memory empty = new bytes32[](0);
            assertFalse(
                family == 2
                    ? LibBMT.verify(c.root, 1, 0, c.elements[0], empty, address(0))
                    : family == 1
                        ? LibMMB.verify(c.root, 1, 0, c.elements[0], empty, address(0))
                        : LibMMR.verify(c.root, 1, 0, c.elements[0], empty, address(0))
            );
            c.root = family == 2
                ? keccak256(abi.encodePacked(uint32(1), keccak256(abi.encodePacked(uint32(0), c.elements[0]))))
                : keccak256(abi.encodePacked(uint64(1), keccak256(abi.encodePacked(uint64(0), c.elements[0]))));
            for (uint8 mode; mode < 3; ++mode) {
                c.mode = mode;
                for (uint256 location; location < 2; ++location) {
                    assertFalse(family == 2 ? this.bmtVerify(c, location != 0) : harness.checked(c, location != 0));
                }
            }
        }
    }

    /// @dev External hashing covers BMT parent preimages, odd duplication, and the empty inner root.
    function test_RawAdapterBmtOddAndEmpty() public view {
        CompatibilityCase memory c;
        c.leaves = 3;
        c.elements = new bytes32[](1);
        c.elements[0] = bytes32(uint256(42));
        c.indices = new uint256[](1);
        c.indices[0] = c.start = 2;
        c.proof = new bytes32[](1);
        c.proof[0] = sha256(
            abi.encodePacked(
                sha256(abi.encodePacked(uint32(0), bytes32(uint256(11)))),
                sha256(abi.encodePacked(uint32(1), bytes32(uint256(22))))
            )
        );
        bytes32 leaf = sha256(abi.encodePacked(uint32(2), c.elements[0]));
        c.root = sha256(
            abi.encodePacked(uint32(3), sha256(abi.encodePacked(c.proof[0], sha256(abi.encodePacked(leaf, leaf)))))
        );
        for (uint8 mode; mode < 3; ++mode) {
            c.mode = mode;
            assertTrue(this.bmtVerify(c, false));
            assertTrue(this.bmtVerify(c, true));
        }
        c.leaves = c.start = 0;
        c.elements = c.proof = new bytes32[](0);
        c.indices = new uint256[](0);
        c.root = sha256(abi.encodePacked(uint32(0), sha256("")));
        for (uint8 mode; mode < 3; mode += 2) {
            c.mode = mode;
            assertTrue(this.bmtVerify(c, false));
            assertTrue(this.bmtVerify(c, true));
        }
    }

    /// @dev Compare every slice of two preimage words with independently encoded bytes.
    function testFuzz_HashPreimage(bytes32 a, bytes32 b, uint8 offsetSeed, uint8 lengthSeed) public view {
        uint256 offset = uint256(offsetSeed) % 65;
        uint256 length = uint256(lengthSeed) % (65 - offset);
        bytes memory words = abi.encodePacked(a, b);
        bytes memory input = new bytes(length);
        for (uint256 i; i < length; ++i) {
            input[i] = words[offset + i];
        }
        for (uint256 algorithm; algorithm < 3; ++algorithm) {
            address target = algorithm == 0 ? address(0) : algorithm == 1 ? address(2) : _hasher();
            bytes32 expected = algorithm == 0 ? keccak256(input) : sha256(input);
            assertEq(Common.hash(a, b, offset, length, target), expected);
        }
    }

    /// @dev Hash target selection depends only on the address's low 160 bits.
    function test_DirtyHasherAddress() public view {
        for (uint256 algorithm; algorithm < 3; ++algorithm) {
            address target = algorithm == 0 ? address(0) : algorithm == 1 ? address(2) : _hasher();
            assembly ("memory-safe") { target := or(target, shl(160, not(0))) }
            bytes memory input = hex"00112233445566778899";
            bytes32 expected = algorithm == 0 ? keccak256(input) : sha256(input);
            assertEq(Common.hash(hex"00112233445566778899", 0, 0, input.length, target), expected);
            for (uint256 family; family < 3; ++family) {
                CompatibilityCase memory c = singleCase(family == 1, family == 2);
                if (algorithm == 0) {
                    c.root = family == 2
                        ? keccak256(abi.encodePacked(uint32(1), keccak256(abi.encodePacked(uint32(0), c.elements[0]))))
                        : keccak256(abi.encodePacked(uint64(1), keccak256(abi.encodePacked(uint64(0), c.elements[0]))));
                }
                if (family == 2) {
                    assertTrue(LibBMT.verify(c.root, 1, 0, c.elements[0], c.proof, target));
                    assertTrue(LibBMT.verifyRange(c.root, 1, 0, c.elements, c.proof, target));
                    assertTrue(LibBMT.verifyMulti(c.root, 1, c.indices, c.elements, c.proof, target));
                } else if (family == 1) {
                    assertTrue(LibMMB.verify(c.root, 1, 0, c.elements[0], c.proof, target));
                    assertTrue(LibMMB.verifyRange(c.root, 1, 0, c.elements, c.proof, target));
                    assertTrue(
                        LibMMB.verifyMulti(
                            c.root,
                            1,
                            c.indices,
                            c.elements,
                            c.positions,
                            c.proof,
                            LibMerkle.Bagging.ForwardFold,
                            0,
                            target
                        )
                    );
                } else {
                    assertTrue(LibMMR.verify(c.root, 1, 0, c.elements[0], c.proof, target));
                    assertTrue(LibMMR.verifyRange(c.root, 1, 0, c.elements, c.proof, target));
                    assertTrue(
                        LibMMR.verifyMulti(
                            c.root,
                            1,
                            c.indices,
                            c.elements,
                            c.positions,
                            c.proof,
                            LibMerkle.Bagging.ForwardFold,
                            0,
                            target
                        )
                    );
                }
            }
        }
    }

    /// @dev Every hashing entrypoint rejects call failure and responses other than exactly 32 bytes.
    function test_InvalidHasherResponses() public {
        for (uint256 response; response < 6; ++response) {
            bytes memory code;
            if (response != 0) {
                uint256 length = response == 1 ? 0 : response == 2 ? 31 : response == 3 ? 33 : 64;
                code = address(new InvalidHasher(length, response == 5)).code;
            }
            vm.etch(_hasher(), code);
            for (uint256 family; family < 3; ++family) {
                CompatibilityCase memory c = singleCase(family == 1, family == 2);
                for (uint8 mode; mode < 3; ++mode) {
                    c.mode = mode;
                    for (uint256 location; location < 2; ++location) {
                        vm.expectRevert(Common.HashFailed.selector);
                        if (family == 2) this.bmtVerify(c, location != 0);
                        else harness.verify(c, location != 0, false);
                    }
                }
            }
        }
    }

    /// @dev STATICCALL forbids a hasher from changing storage even when its output would be valid.
    function test_HasherCannotWriteStorage() public {
        vm.etch(_hasher(), address(new WritingHasher()).code);
        for (uint256 family; family < 3; ++family) {
            CompatibilityCase memory c = singleCase(family == 1, family == 2);
            for (uint8 mode; mode < 3; ++mode) {
                c.mode = mode;
                for (uint256 location; location < 2; ++location) {
                    bytes memory input = family == 2
                        ? abi.encodeCall(this.bmtVerify, (c, location != 0))
                        : abi.encodeCall(harness.verify, (c, location != 0, false));
                    (bool success, bytes memory result) =
                        (family == 2 ? address(this) : address(harness)).staticcall{ gas: 200000 }(input);
                    assertFalse(success);
                    assertEq(result, abi.encodeWithSelector(Common.HashFailed.selector));
                }
            }
        }
        assertEq(WritingHasher(_hasher()).writes(), 0);
    }
}
