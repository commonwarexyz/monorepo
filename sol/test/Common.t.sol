// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.15;

import { Test } from "forge-std/Test.sol";
import { LibMerkle } from "../src/merkle/LibMerkle.sol";
import { LibBMT } from "../src/merkle/LibBMT.sol";
import { LibMMR } from "../src/merkle/LibMMR.sol";
import { LibMMB } from "../src/merkle/LibMMB.sol";

enum ProofKind {
    Range,
    Single,
    Multi
}

enum InputLocation {
    Memory,
    Calldata
}

enum GenerationMode {
    Materialized,
    Synthetic
}

enum Encoding {
    Fixed,
    Variable
}

enum BLSVariant {
    MinSig,
    MinPk
}

/// @dev QMDB roots commit to operations alone or to both operations and activity.
enum RootKind {
    Operations,
    Current
}

/// @dev Virtual constants specialize verifier callers without a runtime hasher parameter.
abstract contract HashSelection {
    function _hasher() internal pure virtual returns (address);

    /// @dev Build reference digests independently of the verifier's hashing implementation.
    /// Test targets use native Keccak256 or SHA256 through the precompile and raw adapters.
    function _hash(bytes memory input) internal pure returns (bytes32) {
        return _hasher() == address(0) ? keccak256(input) : sha256(input);
    }
}

abstract contract HashTest is Test, HashSelection {
    /// @dev Ask the Rust oracle to use the same hash algorithm as the verifier.
    function _ffi(string[] memory args) internal returns (bytes memory) {
        string[] memory selected = new string[](args.length + 2);
        for (uint256 i; i < args.length; ++i) {
            selected[i < 2 ? i : i + 2] = args[i];
        }
        selected[2] = "--hash";
        selected[3] = _hasher() == address(0) ? "keccak256" : "sha256";
        return vm.ffi(selected);
    }

    /// @dev Keep gas snapshots for distinct hashing algorithms in separate groups.
    function _group(string memory family) internal pure returns (string memory) {
        return string.concat(family, _hasher() == address(0) ? "Keccak256" : "Sha256");
    }
}

/// @dev A concrete suite selects one append family for its fixtures and verifier.
abstract contract QMDBTest is HashTest {
    function _family() internal pure virtual returns (LibMerkle.Family);
}

/// @dev Shared FFI arguments select production unordered codecs and proof families.
abstract contract UnorderedOracle is QMDBTest {
    /// @dev Return an Any tuple, or a Current tuple for the selected activity chunk size.
    function unorderedFixture(
        uint256 leaves,
        uint256 location,
        uint256 floor,
        string memory encoding,
        string memory operation,
        string memory history,
        RootKind rootKind,
        uint256 valueLength,
        uint256 chunkBytes
    ) internal returns (bytes memory) {
        bool update = keccak256(bytes(operation)) == keccak256("update");
        assertEq(bytes(history).length != 0, update, "history is required only for updates");
        bool variableLength = keccak256(bytes(encoding)) == keccak256("variable");
        if (!variableLength) assertEq(valueLength, 0, "fixed encoding has no variable value length");
        string[] memory args =
            new string[](19 + (rootKind == RootKind.Current ? 2 : 0) + (update ? 2 : 0) + (variableLength ? 2 : 0));
        args[0] = string.concat(vm.projectRoot(), "/../target/release/commonware-sol-fuzz");
        args[1] = "qmdb";
        args[2] = "unordered";
        args[3] = "--leaves";
        args[4] = vm.toString(leaves);
        args[5] = "--location";
        args[6] = vm.toString(location);
        args[7] = "--seed";
        args[8] = "71";
        args[9] = "--inactivity-floor";
        args[10] = vm.toString(floor);
        args[11] = "--family";
        args[12] = _family() == LibMerkle.Family.MMB ? "mmb" : "mmr";
        args[13] = "--encoding";
        args[14] = encoding;
        args[15] = "--operation";
        args[16] = operation;
        args[17] = "--root";
        args[18] = rootKind == RootKind.Operations ? "operations" : "current";
        uint256 offset = 19;
        if (rootKind == RootKind.Current) {
            args[offset++] = "--chunk-bytes";
            args[offset++] = vm.toString(chunkBytes);
        } else {
            assertEq(chunkBytes, 0, "operations roots have no activity chunks");
        }
        if (update) {
            args[offset++] = "--history";
            args[offset++] = history;
        }
        if (variableLength) {
            args[offset++] = "--value-length";
            args[offset] = vm.toString(valueLength);
        }
        return _ffi(args);
    }
}

struct RootPolicyCase {
    bytes32 root;
    uint256 leaves;
    uint256 start;
    uint256 inactive;
    LibMerkle.Family family;
    LibMerkle.Bagging bagging;
    ProofKind proofKind;
    uint256[] indices;
    uint256[] positions;
    bytes32[] elements;
    bytes32[] proof;
}

/// @dev Exercises policy-aware memory and calldata entrypoints with caller-owned inputs and reusable scratch.
abstract contract RootPolicyHarness is HashTest {
    function memoryVerify(
        RootPolicyCase calldata c,
        uint256[] memory indices,
        uint256[] memory positions,
        bytes32[] memory elements,
        bytes32[] memory proof
    ) internal view returns (bool) {
        if (c.proofKind == ProofKind.Multi) {
            return c.family == LibMerkle.Family.MMB
                ? LibMMB.verifyMulti(
                    c.root, c.leaves, indices, elements, positions, proof, c.bagging, c.inactive, _hasher()
                )
                : LibMMR.verifyMulti(
                    c.root, c.leaves, indices, elements, positions, proof, c.bagging, c.inactive, _hasher()
                );
        }
        if (c.proofKind == ProofKind.Single) {
            return c.family == LibMerkle.Family.MMB
                ? LibMMB.verify(c.root, c.leaves, c.start, elements[0], proof, c.bagging, c.inactive, _hasher())
                : LibMMR.verify(c.root, c.leaves, c.start, elements[0], proof, c.bagging, c.inactive, _hasher());
        }
        return c.family == LibMerkle.Family.MMB
            ? LibMMB.verifyRange(c.root, c.leaves, c.start, elements, proof, c.bagging, c.inactive, _hasher())
            : LibMMR.verifyRange(c.root, c.leaves, c.start, elements, proof, c.bagging, c.inactive, _hasher());
    }

    function calldataVerify(
        RootPolicyCase calldata c,
        uint256[] calldata indices,
        uint256[] calldata positions,
        bytes32[] calldata elements,
        bytes32[] calldata proof
    ) internal view returns (bool) {
        if (c.proofKind == ProofKind.Multi) {
            return c.family == LibMerkle.Family.MMB
                ? LibMMB.verifyMultiCalldata(
                    c.root, c.leaves, indices, elements, positions, proof, c.bagging, c.inactive, _hasher()
                )
                : LibMMR.verifyMultiCalldata(
                    c.root, c.leaves, indices, elements, positions, proof, c.bagging, c.inactive, _hasher()
                );
        }
        if (c.proofKind == ProofKind.Single) {
            return c.family == LibMerkle.Family.MMB
                ? LibMMB.verifyCalldata(c.root, c.leaves, c.start, elements[0], proof, c.bagging, c.inactive, _hasher())
                : LibMMR.verifyCalldata(c.root, c.leaves, c.start, elements[0], proof, c.bagging, c.inactive, _hasher());
        }
        return c.family == LibMerkle.Family.MMB
            ? LibMMB.verifyRangeCalldata(c.root, c.leaves, c.start, elements, proof, c.bagging, c.inactive, _hasher())
            : LibMMR.verifyRangeCalldata(c.root, c.leaves, c.start, elements, proof, c.bagging, c.inactive, _hasher());
    }

    function verify(RootPolicyCase calldata c, InputLocation inputLocation, bool sliced) external view returns (bool) {
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
        return inputLocation == InputLocation.Calldata
            ? calldataVerify(c, indices, positions, elements, proof)
            : memoryVerify(c, indices, positions, elements, proof);
    }

    function checked(RootPolicyCase calldata c, InputLocation inputLocation) external view returns (bool valid) {
        RootPolicyCase memory inputs = c;
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
            bool result = inputLocation == InputLocation.Calldata
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
        bool later = inputLocation == InputLocation.Calldata
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
    function referenceRoot(bytes32[] memory elements, LibMerkle.Family family) internal pure returns (bytes32) {
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
                if (family == LibMerkle.Family.MMB) break;
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
        LibMerkle.Family family,
        bytes32 root,
        uint256 leaves,
        uint256 start,
        bytes32[] memory elements,
        bytes32[] memory proof
    ) public view returns (bool valid) {
        valid = family == LibMerkle.Family.MMB
            ? LibMMB.verifyRange(root, leaves, start, elements, proof, LibMerkle.Bagging.ForwardFold, 0, _hasher())
            : LibMMR.verifyRange(root, leaves, start, elements, proof, LibMerkle.Bagging.ForwardFold, 0, _hasher());
        assertEq(valid, this.calldataRange(family, root, leaves, start, elements, proof), "range calldata disagreement");
    }

    function verifySingle(
        LibMerkle.Family family,
        bytes32 root,
        uint256 leaves,
        uint256 index,
        bytes32 element,
        bytes32[] memory proof
    ) public view returns (bool valid) {
        valid = family == LibMerkle.Family.MMB
            ? LibMMB.verify(root, leaves, index, element, proof, LibMerkle.Bagging.ForwardFold, 0, _hasher())
            : LibMMR.verify(root, leaves, index, element, proof, LibMerkle.Bagging.ForwardFold, 0, _hasher());
        assertEq(
            valid, this.calldataSingle(family, root, leaves, index, element, proof), "single calldata disagreement"
        );
    }

    function calldataRange(
        LibMerkle.Family family,
        bytes32 root,
        uint256 leaves,
        uint256 start,
        bytes32[] calldata elements,
        bytes32[] calldata proof
    ) external view returns (bool) {
        return family == LibMerkle.Family.MMB
            ? LibMMB.verifyRangeCalldata(
                root, leaves, start, elements, proof, LibMerkle.Bagging.ForwardFold, 0, _hasher()
            )
            : LibMMR.verifyRangeCalldata(
                root, leaves, start, elements, proof, LibMerkle.Bagging.ForwardFold, 0, _hasher()
            );
    }

    function calldataSingle(
        LibMerkle.Family family,
        bytes32 root,
        uint256 leaves,
        uint256 index,
        bytes32 element,
        bytes32[] calldata proof
    ) external view returns (bool) {
        return family == LibMerkle.Family.MMB
            ? LibMMB.verifyCalldata(root, leaves, index, element, proof, LibMerkle.Bagging.ForwardFold, 0, _hasher())
            : LibMMR.verifyCalldata(root, leaves, index, element, proof, LibMerkle.Bagging.ForwardFold, 0, _hasher());
    }

    function slicedCalldata(
        LibMerkle.Family family,
        bytes32 root,
        uint256 leaves,
        uint256 start,
        bytes32[] calldata elements,
        bytes32[] calldata proof,
        ProofKind proofKind
    ) external view returns (bool) {
        assertTrue(proofKind != ProofKind.Multi, "single or range proof required");
        elements = elements[1:elements.length - 1];
        proof = proof[1:proof.length - 1];
        if (proofKind == ProofKind.Single) {
            return family == LibMerkle.Family.MMB
                ? LibMMB.verifyCalldata(
                    root, leaves, start, elements[0], proof, LibMerkle.Bagging.ForwardFold, 0, _hasher()
                )
                : LibMMR.verifyCalldata(
                    root, leaves, start, elements[0], proof, LibMerkle.Bagging.ForwardFold, 0, _hasher()
                );
        }
        return family == LibMerkle.Family.MMB
            ? LibMMB.verifyRangeCalldata(
                root, leaves, start, elements, proof, LibMerkle.Bagging.ForwardFold, 0, _hasher()
            )
            : LibMMR.verifyRangeCalldata(
                root, leaves, start, elements, proof, LibMerkle.Bagging.ForwardFold, 0, _hasher()
            );
    }

    function checkedVerification(
        LibMerkle.Family family,
        bytes32 root,
        uint256 leaves,
        uint256 start,
        bytes32[] memory elements,
        bytes32[] memory proof,
        ProofKind proofKind
    ) public returns (bool valid) {
        valid = this.checkedMemoryVerification(
            family, root, leaves, start, elements, proof, proofKind, InputLocation.Memory
        );
        assertEq(
            valid,
            this.checkedMemoryVerification(
                family, root, leaves, start, elements, proof, proofKind, InputLocation.Calldata
            )
        );
    }

    /// @dev Caller-owned arrays precede fresh DFS scratch. Inspect scratch before any subsequent allocation.
    function checkedMemoryVerification(
        LibMerkle.Family family,
        bytes32 root,
        uint256 leaves,
        uint256 start,
        bytes32[] calldata elements,
        bytes32[] calldata proof,
        ProofKind proofKind,
        InputLocation inputLocation
    ) external returns (bool valid) {
        assertTrue(proofKind != ProofKind.Multi, "single or range proof required");
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
        if (inputLocation == InputLocation.Calldata) {
            if (proofKind == ProofKind.Single) {
                valid = family == LibMerkle.Family.MMB
                    ? LibMMB.verifyCalldata(
                        root, leaves, start, elements[0], proof, LibMerkle.Bagging.ForwardFold, 0, _hasher()
                    )
                    : LibMMR.verifyCalldata(
                        root, leaves, start, elements[0], proof, LibMerkle.Bagging.ForwardFold, 0, _hasher()
                    );
            } else {
                valid = family == LibMerkle.Family.MMB
                    ? LibMMB.verifyRangeCalldata(
                        root, leaves, start, elements, proof, LibMerkle.Bagging.ForwardFold, 0, _hasher()
                    )
                    : LibMMR.verifyRangeCalldata(
                        root, leaves, start, elements, proof, LibMerkle.Bagging.ForwardFold, 0, _hasher()
                    );
            }
        } else if (proofKind == ProofKind.Single) {
            valid = family == LibMerkle.Family.MMB
                ? LibMMB.verify(
                    root, leaves, start, memoryElements[0], memoryProof, LibMerkle.Bagging.ForwardFold, 0, _hasher()
                )
                : LibMMR.verify(
                    root, leaves, start, memoryElements[0], memoryProof, LibMerkle.Bagging.ForwardFold, 0, _hasher()
                );
        } else {
            valid = family == LibMerkle.Family.MMB
                ? LibMMB.verifyRange(
                    root, leaves, start, memoryElements, memoryProof, LibMerkle.Bagging.ForwardFold, 0, _hasher()
                )
                : LibMMR.verifyRange(
                    root, leaves, start, memoryElements, memoryProof, LibMerkle.Bagging.ForwardFold, 0, _hasher()
                );
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
            proofKind == ProofKind.Single
                ? verifySingle(family, root, leaves, start, elements[0], memoryProof)
                : verifyRange(family, root, leaves, start, memoryElements, memoryProof),
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

    RootPolicyHarness internal harness;

    function checkCalldataSlices(LibMerkle.Family family, bytes32 a, bytes32 b) internal view {
        bytes32[] memory leaves = new bytes32[](2);
        leaves[0] = a;
        leaves[1] = b;
        bytes32 root = referenceRoot(leaves, family);
        bytes32[] memory elements = new bytes32[](3);
        bytes32[] memory proof = new bytes32[](3);
        elements[0] = proof[0] = bytes32(type(uint256).max);
        elements[2] = proof[2] = bytes32(type(uint256).max - 1);
        elements[1] = a;
        proof[1] = _hash(abi.encodePacked(uint64(1), b));
        for (uint256 mode; mode <= uint256(ProofKind.Single); ++mode) {
            ProofKind proofKind = ProofKind(mode);
            assertTrue(this.slicedCalldata(family, root, 2, 0, elements, proof, proofKind));
            assertFalse(this.slicedCalldata(family, root ^ bytes32(uint256(1)), 2, 0, elements, proof, proofKind));
        }
    }

    function checkFullRange(LibMerkle.Family family, uint8 size, bytes32 seed) internal view {
        bytes32[] memory elements = new bytes32[](uint256(size) + 1);
        for (uint256 i; i < elements.length; ++i) {
            elements[i] = keccak256(abi.encode(seed, i));
        }
        bytes32 root = referenceRoot(elements, family);
        bytes32[] memory proof = new bytes32[](0);
        assertTrue(verifyRange(family, root, elements.length, 0, elements, proof));
        elements[size] ^= bytes32(uint256(1));
        assertFalse(verifyRange(family, root, elements.length, 0, elements, proof));
    }

    function checkSingleLeaf(LibMerkle.Family family, bytes32 element) internal view {
        bytes32 root = _hash(abi.encodePacked(uint64(1), _hash(abi.encodePacked(uint64(0), element))));
        bytes32[] memory proof = new bytes32[](0);
        assertTrue(verifySingle(family, root, 1, 0, element, proof));
        assertFalse(verifySingle(family, root, 1, 1, element, proof));
        assertFalse(verifySingle(family, root, 0, 0, element, proof));
        assertFalse(verifySingle(family, root, 1, type(uint256).max, element, proof));
    }

    function checkTwoLeaves(LibMerkle.Family family, bytes32 a, bytes32 b) internal view {
        bytes32[] memory elements = new bytes32[](2);
        elements[0] = a;
        elements[1] = b;
        bytes32 root = referenceRoot(elements, family);
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = _hash(abi.encodePacked(uint64(1), b));
        assertTrue(verifySingle(family, root, 2, 0, a, proof));
        proof[0] = _hash(abi.encodePacked(uint64(0), a));
        assertTrue(verifySingle(family, root, 2, 1, b, proof));
        proof[0] ^= bytes32(uint256(1));
        assertFalse(verifySingle(family, root, 2, 1, b, proof));
    }

    function checkInvalidBounds(LibMerkle.Family family, uint256 leaves, uint256 start) internal view {
        bytes32[] memory elements = new bytes32[](1);
        bytes32[] memory proof = new bytes32[](0);
        uint256 maxLeaves = family == LibMerkle.Family.MMB ? 0x400000000000001e : 0x4000000000000000;
        if (leaves > maxLeaves || start >= leaves) {
            assertFalse(verifyRange(family, bytes32(0), leaves, start, elements, proof));
        }
        assertFalse(verifyRange(family, bytes32(0), 1, type(uint256).max, elements, proof));
    }

    function checkEmptyTree(LibMerkle.Family family) internal view {
        bytes32[] memory empty = new bytes32[](0);
        bytes32 root = _hash(abi.encodePacked(uint64(0)));
        assertTrue(verifyRange(family, root, 0, 0, empty, empty));
        assertFalse(verifyRange(family, root, 1, 0, empty, empty));
    }

    function checkMemoryExitPaths(LibMerkle.Family family) internal {
        bytes32[] memory elements = new bytes32[](1);
        elements[0] = bytes32(uint256(42));
        bytes32[] memory empty = new bytes32[](0);
        bytes32 root = referenceRoot(elements, family);
        for (uint256 mode; mode <= uint256(ProofKind.Single); ++mode) {
            ProofKind proofKind = ProofKind(mode);
            assertTrue(checkedVerification(family, root, 1, 0, elements, empty, proofKind));
            assertFalse(checkedVerification(family, root ^ bytes32(uint256(1)), 1, 0, elements, empty, proofKind));
            // A leftmost leaf is hashed before its missing right sibling is requested.
            assertFalse(checkedVerification(family, bytes32(0), 2, 0, elements, empty, proofKind));
            assertFalse(checkedVerification(family, root, 1, 1, elements, empty, proofKind));
            assertFalse(checkedVerification(family, root, type(uint256).max, 0, elements, empty, proofKind));
            assertFalse(checkedVerification(family, root, 1, type(uint256).max, elements, empty, proofKind));
        }
        assertTrue(checkedVerification(family, _hash(abi.encodePacked(uint64(0))), 0, 0, empty, empty, ProofKind.Range));
        assertFalse(checkedVerification(family, root, 1, 0, empty, empty, ProofKind.Range));
    }

    function checkMemorySafety(LibMerkle.Family family, uint8 n, bytes32 seed, bool malformed) internal {
        bytes32[] memory elements = new bytes32[](uint256(n) + 1);
        for (uint256 i; i < elements.length; ++i) {
            elements[i] = keccak256(abi.encode(seed, i));
        }
        bytes32 root = referenceRoot(elements, family);
        bytes32[] memory proof = new bytes32[](malformed ? 1 : 0);
        assertEq(
            this.checkedVerification(family, root, elements.length, 0, elements, proof, ProofKind.Range), !malformed
        );
    }

    function generate(
        LibMerkle.Family family,
        uint256 leaves,
        uint256 start,
        uint256 length,
        uint64 seed,
        GenerationMode generation
    ) internal returns (Case memory c) {
        string[] memory args = new string[](17);
        args[0] = string.concat(vm.projectRoot(), "/../target/release/commonware-sol-fuzz");
        args[1] = "merkle";
        args[2] = generation == GenerationMode.Synthetic ? "synthetic" : "generate";
        args[3] = "--family";
        args[4] = family == LibMerkle.Family.MMB ? "mmb" : "mmr";
        args[5] = "--leaf-count";
        args[6] = vm.toString(leaves);
        args[7] = "--start";
        args[8] = vm.toString(start);
        args[9] = "--length";
        args[10] = vm.toString(length);
        args[11] = "--seed";
        args[12] = vm.toString(uint256(seed));
        args[13] = "--bagging";
        args[14] = "forward";
        args[15] = "--inactive-peaks";
        args[16] = "0";
        (c.root, c.elements, c.proof, c.leaves) = abi.decode(_ffi(args), (bytes32, bytes32[], bytes32[], uint256));
        assertEq(c.leaves, leaves);
    }

    function rustCheck(LibMerkle.Family family, Case memory c, uint256 start) internal returns (bool) {
        string[] memory args = new string[](11);
        args[0] = string.concat(vm.projectRoot(), "/../target/release/commonware-sol-fuzz");
        args[1] = "merkle";
        args[2] = "check";
        args[3] = "--family";
        args[4] = family == LibMerkle.Family.MMB ? "mmb" : "mmr";
        args[5] = "--abi";
        args[6] = vm.toString(abi.encode(c.root, c.leaves, start, c.elements, c.proof));
        args[7] = "--bagging";
        args[8] = "forward";
        args[9] = "--inactive-peaks";
        args[10] = "0";
        return abi.decode(_ffi(args), (bool));
    }

    function compare(LibMerkle.Family family, Case memory c, uint256 start) internal returns (bool accepted) {
        accepted = verifyRange(family, c.root, c.leaves, start, c.elements, c.proof);
        assertEq(accepted, rustCheck(family, c, start), "Solidity / Commonware disagreement");
        if (c.elements.length == 1) {
            assertEq(accepted, verifySingle(family, c.root, c.leaves, start, c.elements[0], c.proof));
        }
    }

    function exercise(LibMerkle.Family family, Case memory c, uint256 start, uint256 mutation) internal {
        assertTrue(compare(family, c, start));
        assertTrue(this.checkedVerification(family, c.root, c.leaves, start, c.elements, c.proof, ProofKind.Range));
        if (c.elements.length == 1) {
            assertTrue(this.checkedVerification(family, c.root, c.leaves, start, c.elements, c.proof, ProofKind.Single));
        }
        assertFalse(compare(family, c, start + 1));
        uint256 leaves = c.leaves;
        c.leaves ^= 1;
        assertFalse(compare(family, c, start));
        c.leaves = leaves;
        bytes32 root = c.root;
        c.root ^= bytes32(uint256(1));
        assertFalse(compare(family, c, start));
        assertFalse(this.checkedVerification(family, c.root, c.leaves, start, c.elements, c.proof, ProofKind.Range));
        if (c.elements.length == 1) {
            assertFalse(
                this.checkedVerification(family, c.root, c.leaves, start, c.elements, c.proof, ProofKind.Single)
            );
        }
        c.root = root;
        if (c.elements.length != 0) {
            uint256 i = mutation % c.elements.length;
            c.elements[i] ^= bytes32(uint256(1));
            assertFalse(compare(family, c, start));
            c.elements[i] ^= bytes32(uint256(1));
        }
        if (c.proof.length != 0) {
            uint256 i = mutation % c.proof.length;
            c.proof[i] ^= bytes32(uint256(1));
            assertFalse(compare(family, c, start));
            c.proof[i] ^= bytes32(uint256(1));
            bytes32[] memory proof = c.proof;
            c.proof = new bytes32[](proof.length - 1);
            for (uint256 j; j < c.proof.length; ++j) {
                c.proof[j] = proof[j];
            }
            assertFalse(compare(family, c, start));
            assertFalse(this.checkedVerification(family, c.root, c.leaves, start, c.elements, c.proof, ProofKind.Range));
            if (c.elements.length == 1) {
                assertFalse(
                    this.checkedVerification(family, c.root, c.leaves, start, c.elements, c.proof, ProofKind.Single)
                );
            }
            c.proof = proof;
        }
        bytes32[] memory extra = new bytes32[](c.proof.length + 1);
        for (uint256 i; i < c.proof.length; ++i) {
            extra[i] = c.proof[i];
        }
        c.proof = extra;
        assertFalse(compare(family, c, start));
    }

    function checkDifferentialRange(LibMerkle.Family family, uint16 n, uint16 s, uint16 len, uint64 seed) internal {
        uint256 leaves = uint256(n) % 512 + 1;
        uint256 start = uint256(s) % leaves;
        uint256 length = uint256(len) % (leaves - start) + 1;
        exercise(family, generate(family, leaves, start, length, seed, GenerationMode.Materialized), start, seed);
    }

    function checkDifferentialIndividual(LibMerkle.Family family, uint16 n, uint16 s, uint64 seed) internal {
        uint256 leaves = uint256(n) % 1024 + 1;
        uint256 start = uint256(s) % leaves;
        exercise(family, generate(family, leaves, start, 1, seed, GenerationMode.Materialized), start, seed);
    }

    function checkDifferentialDeep(LibMerkle.Family family, uint8 exponent, uint64 offset, uint64 seed) internal {
        uint256 leaves = uint256(1) << (uint256(exponent) % 62 + 1);
        if (seed & 1 != 0) --leaves;
        uint256 start = uint256(offset) % leaves;
        uint256 length = leaves - start < 4 ? leaves - start : 4;
        exercise(family, generate(family, leaves, start, length, seed, GenerationMode.Synthetic), start, seed);
    }

    function checkDifferentialPositionBitBoundaries(LibMerkle.Family family) internal {
        for (uint256 bit = 1; bit < 62; ++bit) {
            uint256 boundary = uint256(1) << bit;
            Case memory c = generate(family, boundary + 1, boundary - 2, 3, 7, GenerationMode.Synthetic);
            assertTrue(compare(family, c, boundary - 2));
        }
    }

    function checkDifferentialMaximumSize(LibMerkle.Family family) internal {
        uint256 leaves = family == LibMerkle.Family.MMB ? 0x400000000000001e : 0x4000000000000000;
        exercise(family, generate(family, leaves, 0, 1, 1, GenerationMode.Synthetic), 0, 0);
        exercise(family, generate(family, leaves, leaves / 2 - 1, 4, 2, GenerationMode.Synthetic), leaves / 2 - 1, 1);
        exercise(family, generate(family, leaves, leaves - 1, 1, 3, GenerationMode.Synthetic), leaves - 1, 0);
    }

    function checkDifferentialMalformed(
        LibMerkle.Family family,
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
        compare(family, Case(root, elements, proof, leaves), start);
    }

    function checkDifferentialSmallRanges(LibMerkle.Family family) internal {
        for (uint256 leaves = 1; leaves <= 12; ++leaves) {
            for (uint256 start; start < leaves; ++start) {
                for (uint256 length = 1; length <= leaves - start; ++length) {
                    Case memory c = generate(family, leaves, start, length, 7, GenerationMode.Materialized);
                    assertTrue(compare(family, c, start));
                }
            }
        }
    }

    function checkDifferentialEmpty(LibMerkle.Family family) internal {
        bytes32[] memory empty = new bytes32[](0);
        Case memory c = Case(_hash(abi.encodePacked(uint64(0))), empty, empty, 0);
        assertTrue(compare(family, c, 0));
        assertFalse(compare(family, c, 1));
        c.leaves = 1;
        assertFalse(compare(family, c, 0));
        c.leaves = 0;
        c.proof = new bytes32[](1);
        assertFalse(compare(family, c, 0));
    }

    function checkDifferentialGas(LibMerkle.Family family, IMerkleGasHarness gasHarness) internal {
        Case memory c = generate(family, 1024, 1023, 1, 7, GenerationMode.Materialized);
        bool valid = gasHarness.verify(c.root, c.leaves, 1023, c.elements[0], c.proof);
        vm.snapshotGasLastFrame(_group(family == LibMerkle.Family.MMB ? "MMB" : "MMR"), "single-1024-last-memory");
        assertTrue(valid);
        valid = gasHarness.verifyCalldata(c.root, c.leaves, 1023, c.elements[0], c.proof);
        vm.snapshotGasLastFrame(_group(family == LibMerkle.Family.MMB ? "MMB" : "MMR"), "single-1024-last-calldata");
        assertTrue(valid);
        c = generate(family, 1024, 480, 64, 7, GenerationMode.Materialized);
        valid = gasHarness.verifyRange(c.root, c.leaves, 480, c.elements, c.proof);
        vm.snapshotGasLastFrame(_group(family == LibMerkle.Family.MMB ? "MMB" : "MMR"), "range-1024-middle-64-memory");
        assertTrue(valid);
        valid = gasHarness.verifyRangeCalldata(c.root, c.leaves, 480, c.elements, c.proof);
        vm.snapshotGasLastFrame(_group(family == LibMerkle.Family.MMB ? "MMB" : "MMR"), "range-1024-middle-64-calldata");
        assertTrue(valid);
    }

    function generateRootPolicy(RootPolicyCase memory c, uint256 length, uint64 seed, GenerationMode generation)
        internal
        returns (RootPolicyCase memory)
    {
        string[] memory args = new string[](17);
        args[0] = string.concat(vm.projectRoot(), "/../target/release/commonware-sol-fuzz");
        args[1] = "merkle";
        args[2] = generation == GenerationMode.Synthetic ? "synthetic" : "generate";
        args[3] = "--family";
        args[4] = c.family == LibMerkle.Family.MMB ? "mmb" : "mmr";
        args[5] = "--leaf-count";
        args[6] = vm.toString(c.leaves);
        args[7] = "--start";
        args[8] = vm.toString(c.start);
        args[9] = "--length";
        args[10] = vm.toString(length);
        args[11] = "--seed";
        args[12] = vm.toString(uint256(seed));
        args[13] = "--bagging";
        args[14] = c.bagging == LibMerkle.Bagging.BackwardFold ? "backward" : "forward";
        args[15] = "--inactive-peaks";
        args[16] = vm.toString(c.inactive);
        (c.root, c.elements, c.proof, c.leaves) = abi.decode(_ffi(args), (bytes32, bytes32[], bytes32[], uint256));
        return c;
    }

    function generateMulti(RootPolicyCase memory c, uint64 seed, GenerationMode generation)
        internal
        returns (RootPolicyCase memory)
    {
        string memory locations = vm.toString(c.indices[0]);
        for (uint256 i = 1; i < c.indices.length; ++i) {
            locations = string.concat(locations, ",", vm.toString(c.indices[i]));
        }
        string[] memory args = new string[](15);
        args[0] = string.concat(vm.projectRoot(), "/../target/release/commonware-sol-fuzz");
        args[1] = "merkle";
        args[2] = generation == GenerationMode.Synthetic ? "synthetic-multi" : "generate-multi";
        args[3] = "--family";
        args[4] = c.family == LibMerkle.Family.MMB ? "mmb" : "mmr";
        args[5] = "--leaf-count";
        args[6] = vm.toString(c.leaves);
        args[7] = "--locations";
        args[8] = locations;
        args[9] = "--seed";
        args[10] = vm.toString(uint256(seed));
        args[11] = "--bagging";
        args[12] = c.bagging == LibMerkle.Bagging.BackwardFold ? "backward" : "forward";
        args[13] = "--inactive-peaks";
        args[14] = vm.toString(c.inactive);
        (c.root, c.elements, c.proof, c.leaves, c.positions) =
            abi.decode(_ffi(args), (bytes32, bytes32[], bytes32[], uint256, uint256[]));
        c.proofKind = ProofKind.Multi;
        return c;
    }

    function rustCheckRootPolicy(RootPolicyCase memory c) internal returns (bool) {
        string[] memory args = new string[](11);
        args[0] = string.concat(vm.projectRoot(), "/../target/release/commonware-sol-fuzz");
        args[1] = "merkle";
        args[2] = c.proofKind == ProofKind.Multi ? "check-multi" : "check";
        args[3] = "--family";
        args[4] = c.family == LibMerkle.Family.MMB ? "mmb" : "mmr";
        args[5] = "--abi";
        args[6] = c.proofKind == ProofKind.Multi
            ? vm.toString(abi.encode(c.root, c.leaves, c.indices, c.elements, c.proof, c.positions))
            : vm.toString(abi.encode(c.root, c.leaves, c.start, c.elements, c.proof));
        args[7] = "--bagging";
        args[8] = c.bagging == LibMerkle.Bagging.BackwardFold ? "backward" : "forward";
        args[9] = "--inactive-peaks";
        args[10] = vm.toString(c.inactive);
        return abi.decode(_ffi(args), (bool));
    }

    function compareRootPolicy(RootPolicyCase memory c, bool expected) internal {
        assertEq(rustCheckRootPolicy(c), expected, "Commonware expected result");
        assertEq(harness.checked(c, InputLocation.Memory), expected, "memory disagreement");
        assertEq(harness.checked(c, InputLocation.Calldata), expected, "calldata disagreement");
    }

    function slices(RootPolicyCase memory c, bool expected) internal view {
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
        assertEq(harness.verify(c, InputLocation.Calldata, true), expected, "sliced calldata disagreement");
        c.indices = indices;
        c.positions = positions;
        c.elements = elements;
        c.proof = proof;
    }

    function exerciseRootPolicy(RootPolicyCase memory c) internal {
        compareRootPolicy(c, true);
        slices(c, true);
        c.root ^= bytes32(uint256(1));
        compareRootPolicy(c, false);
        slices(c, false);
        c.root ^= bytes32(uint256(1));
        c.inactive += 1;
        compareRootPolicy(c, false);
        c.inactive -= 1;
        c.leaves += 1;
        compareRootPolicy(c, false);
        c.leaves -= 1;
        if (c.elements.length != 0) {
            c.elements[0] ^= bytes32(uint256(1));
            compareRootPolicy(c, false);
            c.elements[0] ^= bytes32(uint256(1));
        }
        bytes32[] memory proof = c.proof;
        uint256[] memory positions = c.positions;
        if (proof.length != 0) {
            proof[proof.length - 1] ^= bytes32(uint256(1));
            compareRootPolicy(c, false);
            proof[proof.length - 1] ^= bytes32(uint256(1));
            c.proof = new bytes32[](proof.length - 1);
            for (uint256 i; i < c.proof.length; ++i) {
                c.proof[i] = proof[i];
            }
            if (c.proofKind == ProofKind.Multi) {
                c.positions = new uint256[](positions.length - 1);
                for (uint256 i; i < c.positions.length; ++i) {
                    c.positions[i] = positions[i];
                }
            }
            compareRootPolicy(c, false);
        }
        c.proof = new bytes32[](proof.length + 1);
        for (uint256 i; i < proof.length; ++i) {
            c.proof[i] = proof[i];
        }
        if (c.proofKind == ProofKind.Multi) {
            c.positions = new uint256[](positions.length + 1);
            for (uint256 i; i < positions.length; ++i) {
                c.positions[i] = positions[i];
            }
            c.positions[positions.length] = positions.length == 0 ? 0 : positions[positions.length - 1] + 1;
        }
        compareRootPolicy(c, false);
        c.proof = proof;
        c.positions = positions;
    }

    function peakWidths(LibMerkle.Family family, uint256 leaves) internal pure returns (uint256[] memory widths) {
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
                if (family == LibMerkle.Family.MMB) break;
                j = count;
            }
        }
        assembly ("memory-safe") { mstore(widths, count) }
    }

    function checkRootPolicyInactiveBoundaryMatrix(LibMerkle.Family family) internal {
        uint256[] memory widths = peakWidths(family, 31);
        for (uint256 baggingIndex; baggingIndex <= uint256(LibMerkle.Bagging.BackwardFold); ++baggingIndex) {
            for (uint256 inactive; inactive <= widths.length; ++inactive) {
                RootPolicyCase memory c;
                c.proofKind = ProofKind.Range;
                c.family = family;
                c.bagging = LibMerkle.Bagging(baggingIndex);
                c.leaves = 31;
                c.inactive = inactive;
                uint256 boundary;
                for (uint256 peak; peak < widths.length; ++peak) {
                    c.start = boundary;
                    c = generateRootPolicy(c, 1, 11, GenerationMode.Materialized);
                    c.proofKind = ProofKind.Single;
                    compareRootPolicy(c, true);
                    c.proofKind = ProofKind.Range;
                    compareRootPolicy(c, true);
                    boundary += widths[peak];
                    if (boundary < c.leaves) {
                        c.start = boundary - 1;
                        c = generateRootPolicy(c, 2, 11, GenerationMode.Materialized);
                        compareRootPolicy(c, true);
                        slices(c, true);
                    }
                }
            }
        }
    }

    function checkRootPolicyRangeMutations(LibMerkle.Family family) internal {
        for (uint256 baggingIndex; baggingIndex <= uint256(LibMerkle.Bagging.BackwardFold); ++baggingIndex) {
            RootPolicyCase memory c;
            c.proofKind = ProofKind.Range;
            c.family = family;
            c.bagging = LibMerkle.Bagging(baggingIndex);
            c.leaves = 31;
            c.inactive = 2;
            c.start = 15;
            exerciseRootPolicy(generateRootPolicy(c, 12, 7, GenerationMode.Materialized));
            c.start = 30;
            c.proofKind = ProofKind.Single;
            exerciseRootPolicy(generateRootPolicy(c, 1, 7, GenerationMode.Materialized));
        }
    }

    function checkRootPolicyRange(
        LibMerkle.Family family,
        LibMerkle.Bagging bagging,
        uint8 n,
        uint8 s,
        uint8 len,
        uint8 inactive,
        uint64 seed
    ) internal {
        RootPolicyCase memory c;
        c.proofKind = ProofKind.Range;
        c.family = family;
        c.bagging = bagging;
        c.leaves = uint256(n) % 64 + 1;
        c.start = uint256(s) % c.leaves;
        c.inactive = uint256(inactive) % (peakWidths(family, c.leaves).length + 1);
        uint256 length = uint256(len) % (c.leaves - c.start) + 1;
        exerciseRootPolicy(generateRootPolicy(c, length, seed, GenerationMode.Materialized));
    }

    function checkRootPolicyMaximumSize(LibMerkle.Family family) internal {
        for (uint256 baggingIndex; baggingIndex <= uint256(LibMerkle.Bagging.BackwardFold); ++baggingIndex) {
            RootPolicyCase memory c;
            c.proofKind = ProofKind.Range;
            c.family = family;
            c.bagging = LibMerkle.Bagging(baggingIndex);
            c.leaves = c.family == LibMerkle.Family.MMB ? 0x400000000000001e : 0x4000000000000000;
            c.inactive = 1;
            c.start = c.leaves / 2 - 1;
            exerciseRootPolicy(generateRootPolicy(c, 4, 23, GenerationMode.Synthetic));
            c.start = c.leaves - 1;
            c.proofKind = ProofKind.Single;
            exerciseRootPolicy(generateRootPolicy(c, 1, 29, GenerationMode.Synthetic));
        }
    }

    function checkRootPolicyDeep(
        LibMerkle.Family family,
        LibMerkle.Bagging bagging,
        uint8 exponent,
        uint64 offset,
        uint64 seed
    ) internal {
        RootPolicyCase memory c;
        c.proofKind = ProofKind.Range;
        c.family = family;
        c.bagging = bagging;
        c.leaves = (uint256(1) << (uint256(exponent) % 61 + 2)) - 1;
        c.start = uint256(offset) % c.leaves;
        c.inactive = seed % 2;
        exerciseRootPolicy(
            generateRootPolicy(c, c.leaves - c.start < 3 ? c.leaves - c.start : 3, seed, GenerationMode.Synthetic)
        );
    }

    function checkRootPolicyEmpty(LibMerkle.Family family) internal {
        for (uint256 baggingIndex; baggingIndex <= uint256(LibMerkle.Bagging.BackwardFold); ++baggingIndex) {
            for (uint256 proofIndex; proofIndex <= uint256(ProofKind.Multi); proofIndex += 2) {
                ProofKind proofKind = ProofKind(proofIndex);
                RootPolicyCase memory c;
                c.family = family;
                c.bagging = LibMerkle.Bagging(baggingIndex);
                c.proofKind = proofKind;
                c.root = _hash(abi.encodePacked(uint64(0)));
                compareRootPolicy(c, true);
                slices(c, true);
                c.inactive = 1;
                compareRootPolicy(c, false);
                c.inactive = 0;
                c.leaves = 1;
                compareRootPolicy(c, false);
            }
        }
    }

    function checkRootPolicySparseMatrix(LibMerkle.Family family) internal {
        uint256 count = peakWidths(family, 31).length;
        for (uint256 baggingIndex; baggingIndex <= uint256(LibMerkle.Bagging.BackwardFold); ++baggingIndex) {
            for (uint256 inactive; inactive <= count; ++inactive) {
                RootPolicyCase memory c;
                c.family = family;
                c.bagging = LibMerkle.Bagging(baggingIndex);
                c.leaves = 31;
                c.inactive = inactive;
                c.indices = new uint256[](5);
                c.indices[0] = 30;
                c.indices[1] = 0;
                c.indices[2] = 16;
                c.indices[3] = 15;
                c.indices[4] = 16;
                exerciseRootPolicy(generateMulti(c, 17, GenerationMode.Materialized));
            }
        }
    }

    function checkRootPolicySparseWitnessOrdering(LibMerkle.Family family) internal {
        for (uint256 baggingIndex; baggingIndex <= uint256(LibMerkle.Bagging.BackwardFold); ++baggingIndex) {
            RootPolicyCase memory c;
            c.family = family;
            c.bagging = LibMerkle.Bagging(baggingIndex);
            c.leaves = 31;
            c.inactive = 2;
            c.indices = new uint256[](3);
            c.indices[0] = 30;
            c.indices[1] = 3;
            c.indices[2] = 3;
            c = generateMulti(c, 9, GenerationMode.Materialized);
            compareRootPolicy(c, true);
            c.elements[2] ^= bytes32(uint256(1));
            compareRootPolicy(c, false);
            c.elements[2] ^= bytes32(uint256(1));
            (c.proof[0], c.proof[1]) = (c.proof[1], c.proof[0]);
            compareRootPolicy(c, false);
            (c.proof[0], c.proof[1]) = (c.proof[1], c.proof[0]);
            (c.positions[0], c.positions[1]) = (c.positions[1], c.positions[0]);
            compareRootPolicy(c, false);
            (c.positions[0], c.positions[1]) = (c.positions[1], c.positions[0]);
            (c.positions[0], c.positions[1]) = (c.positions[1], c.positions[0]);
            (c.proof[0], c.proof[1]) = (c.proof[1], c.proof[0]);
            compareRootPolicy(c, false);
            (c.positions[0], c.positions[1]) = (c.positions[1], c.positions[0]);
            (c.proof[0], c.proof[1]) = (c.proof[1], c.proof[0]);
            uint256 position = c.positions[1];
            c.positions[1] = c.positions[0];
            compareRootPolicy(c, false);
            c.positions[1] = position;
            c.positions[c.positions.length - 1] = type(uint256).max;
            compareRootPolicy(c, false);
            c = generateMulti(c, 9, GenerationMode.Materialized);
            uint256[] memory indices = c.indices;
            c.indices = new uint256[](2);
            c.indices[0] = indices[0];
            c.indices[1] = indices[1];
            compareRootPolicy(c, false);
            c.indices = indices;
            c.positions = new uint256[](0);
            compareRootPolicy(c, false);
        }
    }

    function checkRootPolicySparse(LibMerkle.Family family, LibMerkle.Bagging bagging, uint8 n, uint64 seed) internal {
        RootPolicyCase memory c;
        c.family = family;
        c.bagging = bagging;
        c.leaves = uint256(n) % 64 + 1;
        c.inactive = uint256(seed) % (peakWidths(family, c.leaves).length + 1);
        c.indices = new uint256[]((uint256(seed) >> 32) % 32 + 1);
        for (uint256 i; i < c.indices.length; ++i) {
            c.indices[i] = uint256(keccak256(abi.encode(seed, i))) % c.leaves;
        }
        exerciseRootPolicy(generateMulti(c, seed, GenerationMode.Materialized));
    }

    function checkRootPolicySparseMaximumSize(LibMerkle.Family family) internal {
        for (uint256 baggingIndex; baggingIndex <= uint256(LibMerkle.Bagging.BackwardFold); ++baggingIndex) {
            RootPolicyCase memory c;
            c.family = family;
            c.bagging = LibMerkle.Bagging(baggingIndex);
            c.leaves = c.family == LibMerkle.Family.MMB ? 0x400000000000001e : 0x4000000000000000;
            c.inactive = 1;
            c.indices = new uint256[](4);
            c.indices[0] = c.leaves - 1;
            c.indices[1] = 0;
            c.indices[2] = c.leaves / 2 - 1;
            c.indices[3] = c.leaves / 2;
            exerciseRootPolicy(generateMulti(c, 31, GenerationMode.Synthetic));
        }
    }

    function checkRootPolicyGas(LibMerkle.Family family) internal {
        for (uint256 baggingIndex; baggingIndex <= uint256(LibMerkle.Bagging.BackwardFold); ++baggingIndex) {
            RootPolicyCase memory c;
            c.proofKind = ProofKind.Range;
            c.family = family;
            c.bagging = LibMerkle.Bagging(baggingIndex);
            c.leaves = 1023;
            c.start = 480;
            c.inactive = 2;
            c = generateRootPolicy(c, 64, 7, GenerationMode.Materialized);
            string memory group = string.concat(c.family == LibMerkle.Family.MMB ? "MMB" : "MMR", "RootPolicy");
            string memory fold = c.bagging == LibMerkle.Bagging.BackwardFold ? "backward" : "forward";
            assertTrue(harness.verify(c, InputLocation.Memory, false));
            vm.snapshotGasLastFrame(_group(group), string.concat(fold, "-inactive-range-memory"));
            assertTrue(harness.verify(c, InputLocation.Calldata, false));
            vm.snapshotGasLastFrame(_group(group), string.concat(fold, "-inactive-range-calldata"));
            c.indices = new uint256[](3);
            c.indices[0] = 0;
            c.indices[1] = 511;
            c.indices[2] = 1022;
            c = generateMulti(c, 7, GenerationMode.Materialized);
            assertTrue(harness.verify(c, InputLocation.Memory, false));
            vm.snapshotGasLastFrame(_group(group), string.concat(fold, "-inactive-sparse-memory"));
            assertTrue(harness.verify(c, InputLocation.Calldata, false));
            vm.snapshotGasLastFrame(_group(group), string.concat(fold, "-inactive-sparse-calldata"));
        }
    }

    function checkRootPolicySparseExactUnion(LibMerkle.Family family) internal {
        for (uint256 baggingIndex; baggingIndex <= uint256(LibMerkle.Bagging.BackwardFold); ++baggingIndex) {
            for (uint256 shape; shape < 5; ++shape) {
                RootPolicyCase memory c;
                c.family = family;
                c.bagging = LibMerkle.Bagging(baggingIndex);
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
                c = generateMulti(c, 43, GenerationMode.Materialized);
                assertGt(c.proof.length, 0, "Rust union includes witnesses for supplied leaves");
                if (shape == 0) {
                    for (uint256 witness; witness < c.proof.length; ++witness) {
                        c.proof[witness] ^= bytes32(uint256(1));
                        compareRootPolicy(c, false);
                        c.proof[witness] ^= bytes32(uint256(1));
                    }
                }
                exerciseRootPolicy(c);
                c.inactive = 0;
                compareRootPolicy(c, false);
            }
        }
    }

    function checkRootPolicyInvalidBounds(LibMerkle.Family family) internal {
        for (uint256 baggingIndex; baggingIndex <= uint256(LibMerkle.Bagging.BackwardFold); ++baggingIndex) {
            for (uint256 proofIndex; proofIndex <= uint256(ProofKind.Multi); ++proofIndex) {
                ProofKind proofKind = ProofKind(proofIndex);
                RootPolicyCase memory c;
                c.family = family;
                c.bagging = LibMerkle.Bagging(baggingIndex);
                c.proofKind = proofKind;
                c.leaves = 1;
                c.elements = new bytes32[](1);
                c.indices = new uint256[](1);
                c = proofKind == ProofKind.Multi
                    ? generateMulti(c, 19, GenerationMode.Materialized)
                    : generateRootPolicy(c, 1, 19, GenerationMode.Materialized);
                c.leaves = (c.family == LibMerkle.Family.MMB ? 0x400000000000001e : 0x4000000000000000) + 1;
                compareRootPolicy(c, false);
                c.leaves = 1;
                c.start = type(uint256).max;
                c.indices[0] = type(uint256).max;
                compareRootPolicy(c, false);
            }
        }
    }

    function checkRootPolicyBinding(LibMerkle.Family family) internal {
        for (uint256 baggingIndex; baggingIndex <= uint256(LibMerkle.Bagging.BackwardFold); ++baggingIndex) {
            RootPolicyCase memory c;
            c.proofKind = ProofKind.Range;
            c.family = family;
            c.bagging = LibMerkle.Bagging(baggingIndex);
            c.leaves = 31;
            c.start = 3;
            c = generateRootPolicy(c, 2, 41, GenerationMode.Materialized);
            bytes32 zeroBoundaryRoot = c.root;
            c.inactive = 1;
            c = generateRootPolicy(c, 2, 41, GenerationMode.Materialized);
            assertNotEq(c.root, zeroBoundaryRoot, "inactive boundary is root bound");
            compareRootPolicy(c, true);
            c.inactive = 0;
            compareRootPolicy(c, false);
            c.inactive = 1;
            c.bagging = c.bagging == LibMerkle.Bagging.ForwardFold
                ? LibMerkle.Bagging.BackwardFold
                : LibMerkle.Bagging.ForwardFold;
            compareRootPolicy(c, false);
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

contract RawRootPolicyHarness is RootPolicyHarness {
    /// @dev Select the raw adapter installed by the test at a fixed non-precompile address.
    function _hasher() internal pure override returns (address) {
        return address(0x123400);
    }
}

/// @dev Test raw external hash targets through the same proof and memory contracts as precompiles.
contract HashAddressTest is MerkleTestCommon {
    enum HashTarget {
        Keccak256,
        Sha256Precompile,
        Sha256Raw
    }

    enum VerifierKind {
        MMR,
        MMB,
        BMT
    }

    /// @dev Select the fixed raw adapter address for verifier calls and SHA-256 reference roots.
    function _hasher() internal pure override returns (address) {
        return address(0x123400);
    }

    /// @dev Install a selector-free SHA-256 adapter and its compatibility harness.
    function setUp() public {
        vm.etch(_hasher(), address(new RawSha256Hasher()).code);
        harness = new RawRootPolicyHarness();
    }

    /// @dev Cover positioned leaf, parent, root and peak preimages with caller memory checks.
    function test_RawAdapterMemorySafety() public {
        for (uint256 i; i <= uint256(LibMerkle.Family.MMB); ++i) {
            LibMerkle.Family family = LibMerkle.Family(i);
            checkMemoryExitPaths(family);
            checkMemorySafety(family, 30, bytes32(uint256(79)), false);
            checkMemorySafety(family, 30, bytes32(uint256(79)), true);
        }
    }

    /// @dev Compare external hashing with Rust across both bagging policies and inactive peaks.
    function test_DifferentialRawAdapterPolicies() public {
        for (uint256 i; i <= uint256(LibMerkle.Family.MMB); ++i) {
            LibMerkle.Family family = LibMerkle.Family(i);
            checkRootPolicyRange(family, LibMerkle.Bagging.ForwardFold, 30, 3, 9, 2, 71);
            checkRootPolicyRange(family, LibMerkle.Bagging.BackwardFold, 30, 3, 9, 2, 71);
            checkRootPolicySparse(family, LibMerkle.Bagging.ForwardFold, 30, 71);
            checkRootPolicySparse(family, LibMerkle.Bagging.BackwardFold, 30, 71);
        }
    }

    /// @dev Build a one-leaf proof shared by the three verification shapes.
    function singleCase(VerifierKind family) internal pure returns (RootPolicyCase memory c) {
        c.proofKind = ProofKind.Single;
        c.bagging = LibMerkle.Bagging.ForwardFold;
        c.family = family == VerifierKind.MMB ? LibMerkle.Family.MMB : LibMerkle.Family.MMR;
        c.leaves = 1;
        c.elements = new bytes32[](1);
        c.elements[0] = bytes32(uint256(42));
        c.indices = new uint256[](1);
        c.root = family == VerifierKind.BMT
            ? sha256(abi.encodePacked(uint32(1), sha256(abi.encodePacked(uint32(0), c.elements[0]))))
            : sha256(abi.encodePacked(uint64(1), sha256(abi.encodePacked(uint64(0), c.elements[0]))));
    }

    /// @dev Exercise each BMT shape and input location against a raw hash address.
    function bmtVerify(RootPolicyCase calldata c, InputLocation inputLocation) external view returns (bool) {
        if (c.proofKind == ProofKind.Single) {
            return inputLocation == InputLocation.Calldata
                ? LibBMT.verifyCalldata(c.root, c.leaves, c.start, c.elements[0], c.proof, _hasher())
                : LibBMT.verify(c.root, c.leaves, c.start, c.elements[0], c.proof, _hasher());
        }
        if (c.proofKind == ProofKind.Multi) {
            return inputLocation == InputLocation.Calldata
                ? LibBMT.verifyMultiCalldata(c.root, c.leaves, c.indices, c.elements, c.proof, _hasher())
                : LibBMT.verifyMulti(c.root, c.leaves, c.indices, c.elements, c.proof, _hasher());
        }
        return inputLocation == InputLocation.Calldata
            ? LibBMT.verifyRangeCalldata(c.root, c.leaves, c.start, c.elements, c.proof, _hasher())
            : LibBMT.verifyRange(c.root, c.leaves, c.start, c.elements, c.proof, _hasher());
    }

    /// @dev Raw adapters accept valid proofs. Using the other algorithm rejects the same root.
    function test_RawAdapterAndCrossHashRejection() public view {
        for (uint256 i; i <= uint256(VerifierKind.BMT); ++i) {
            VerifierKind family = VerifierKind(i);
            RootPolicyCase memory c = singleCase(family);
            for (uint256 proofIndex; proofIndex <= uint256(ProofKind.Multi); ++proofIndex) {
                ProofKind proofKind = ProofKind(proofIndex);
                c.proofKind = proofKind;
                for (uint256 locationIndex; locationIndex <= uint256(InputLocation.Calldata); ++locationIndex) {
                    InputLocation inputLocation = InputLocation(locationIndex);
                    assertTrue(
                        family == VerifierKind.BMT
                            ? this.bmtVerify(c, inputLocation)
                            : harness.checked(c, inputLocation)
                    );
                }
            }
            bytes32[] memory empty = new bytes32[](0);
            assertFalse(
                family == VerifierKind.BMT
                    ? LibBMT.verify(c.root, 1, 0, c.elements[0], empty, address(0))
                    : family == VerifierKind.MMB
                        ? LibMMB.verify(
                            c.root, 1, 0, c.elements[0], empty, LibMerkle.Bagging.ForwardFold, 0, address(0)
                        )
                        : LibMMR.verify(
                                c.root, 1, 0, c.elements[0], empty, LibMerkle.Bagging.ForwardFold, 0, address(0)
                            )
            );
            c.root = family == VerifierKind.BMT
                ? keccak256(abi.encodePacked(uint32(1), keccak256(abi.encodePacked(uint32(0), c.elements[0]))))
                : keccak256(abi.encodePacked(uint64(1), keccak256(abi.encodePacked(uint64(0), c.elements[0]))));
            for (uint256 proofIndex; proofIndex <= uint256(ProofKind.Multi); ++proofIndex) {
                ProofKind proofKind = ProofKind(proofIndex);
                c.proofKind = proofKind;
                for (uint256 locationIndex; locationIndex <= uint256(InputLocation.Calldata); ++locationIndex) {
                    InputLocation inputLocation = InputLocation(locationIndex);
                    assertFalse(
                        family == VerifierKind.BMT
                            ? this.bmtVerify(c, inputLocation)
                            : harness.checked(c, inputLocation)
                    );
                }
            }
        }
    }

    /// @dev External hashing covers BMT parent preimages, odd duplication, and the empty inner root.
    function test_RawAdapterBmtOddAndEmpty() public view {
        RootPolicyCase memory c;
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
        for (uint256 proofIndex; proofIndex <= uint256(ProofKind.Multi); ++proofIndex) {
            ProofKind proofKind = ProofKind(proofIndex);
            c.proofKind = proofKind;
            assertTrue(this.bmtVerify(c, InputLocation.Memory));
            assertTrue(this.bmtVerify(c, InputLocation.Calldata));
        }
        c.leaves = c.start = 0;
        c.elements = c.proof = new bytes32[](0);
        c.indices = new uint256[](0);
        c.root = sha256(abi.encodePacked(uint32(0), sha256("")));
        for (uint256 proofIndex; proofIndex <= uint256(ProofKind.Multi); proofIndex += 2) {
            ProofKind proofKind = ProofKind(proofIndex);
            c.proofKind = proofKind;
            assertTrue(this.bmtVerify(c, InputLocation.Memory));
            assertTrue(this.bmtVerify(c, InputLocation.Calldata));
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
        for (uint256 targetIndex; targetIndex <= uint256(HashTarget.Sha256Raw); ++targetIndex) {
            HashTarget hashTarget = HashTarget(targetIndex);
            address target = hashTarget == HashTarget.Keccak256
                ? address(0)
                : hashTarget == HashTarget.Sha256Precompile ? address(2) : _hasher();
            bytes32 expected = hashTarget == HashTarget.Keccak256 ? keccak256(input) : sha256(input);
            assertEq(LibMerkle.hashSlice(a, b, offset, length, target), expected);
        }
    }

    /// @dev Hash target selection depends only on the address's low 160 bits.
    function test_DirtyHasherAddress() public view {
        for (uint256 targetIndex; targetIndex <= uint256(HashTarget.Sha256Raw); ++targetIndex) {
            HashTarget hashTarget = HashTarget(targetIndex);
            address target = hashTarget == HashTarget.Keccak256
                ? address(0)
                : hashTarget == HashTarget.Sha256Precompile ? address(2) : _hasher();
            assembly ("memory-safe") { target := or(target, shl(160, not(0))) }
            bytes memory input = hex"00112233445566778899";
            bytes32 expected = hashTarget == HashTarget.Keccak256 ? keccak256(input) : sha256(input);
            assertEq(LibMerkle.hashSlice(hex"00112233445566778899", 0, 0, input.length, target), expected);
            for (uint256 i; i <= uint256(VerifierKind.BMT); ++i) {
                VerifierKind family = VerifierKind(i);
                RootPolicyCase memory c = singleCase(family);
                if (hashTarget == HashTarget.Keccak256) {
                    c.root = family == VerifierKind.BMT
                        ? keccak256(abi.encodePacked(uint32(1), keccak256(abi.encodePacked(uint32(0), c.elements[0]))))
                        : keccak256(abi.encodePacked(uint64(1), keccak256(abi.encodePacked(uint64(0), c.elements[0]))));
                }
                if (family == VerifierKind.BMT) {
                    assertTrue(LibBMT.verify(c.root, 1, 0, c.elements[0], c.proof, target));
                    assertTrue(LibBMT.verifyRange(c.root, 1, 0, c.elements, c.proof, target));
                    assertTrue(LibBMT.verifyMulti(c.root, 1, c.indices, c.elements, c.proof, target));
                } else if (family == VerifierKind.MMB) {
                    assertTrue(
                        LibMMB.verify(c.root, 1, 0, c.elements[0], c.proof, LibMerkle.Bagging.ForwardFold, 0, target)
                    );
                    assertTrue(
                        LibMMB.verifyRange(c.root, 1, 0, c.elements, c.proof, LibMerkle.Bagging.ForwardFold, 0, target)
                    );
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
                    assertTrue(
                        LibMMR.verify(c.root, 1, 0, c.elements[0], c.proof, LibMerkle.Bagging.ForwardFold, 0, target)
                    );
                    assertTrue(
                        LibMMR.verifyRange(c.root, 1, 0, c.elements, c.proof, LibMerkle.Bagging.ForwardFold, 0, target)
                    );
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
            for (uint256 i; i <= uint256(VerifierKind.BMT); ++i) {
                VerifierKind family = VerifierKind(i);
                RootPolicyCase memory c = singleCase(family);
                for (uint256 proofIndex; proofIndex <= uint256(ProofKind.Multi); ++proofIndex) {
                    ProofKind proofKind = ProofKind(proofIndex);
                    c.proofKind = proofKind;
                    for (uint256 locationIndex; locationIndex <= uint256(InputLocation.Calldata); ++locationIndex) {
                        InputLocation inputLocation = InputLocation(locationIndex);
                        vm.expectRevert(LibMerkle.HashFailed.selector);
                        if (family == VerifierKind.BMT) this.bmtVerify(c, inputLocation);
                        else harness.verify(c, inputLocation, false);
                    }
                }
            }
        }
    }

    /// @dev STATICCALL forbids a hasher from changing storage even when its output would be valid.
    function test_HasherCannotWriteStorage() public {
        vm.etch(_hasher(), address(new WritingHasher()).code);
        for (uint256 i; i <= uint256(VerifierKind.BMT); ++i) {
            VerifierKind family = VerifierKind(i);
            RootPolicyCase memory c = singleCase(family);
            for (uint256 proofIndex; proofIndex <= uint256(ProofKind.Multi); ++proofIndex) {
                ProofKind proofKind = ProofKind(proofIndex);
                c.proofKind = proofKind;
                for (uint256 locationIndex; locationIndex <= uint256(InputLocation.Calldata); ++locationIndex) {
                    InputLocation inputLocation = InputLocation(locationIndex);
                    bytes memory input = family == VerifierKind.BMT
                        ? abi.encodeCall(this.bmtVerify, (c, inputLocation))
                        : abi.encodeCall(harness.verify, (c, inputLocation, false));
                    (bool success, bytes memory result) =
                        (family == VerifierKind.BMT ? address(this) : address(harness)).staticcall{ gas: 200000 }(input);
                    assertFalse(success);
                    assertEq(result, abi.encodeWithSelector(LibMerkle.HashFailed.selector));
                }
            }
        }
        assertEq(WritingHasher(_hasher()).writes(), 0);
    }
}

contract Keccak256RootPolicyHarness is RootPolicyHarness {
    function _hasher() internal pure override returns (address) {
        return address(0);
    }
}

contract Sha256RootPolicyHarness is RootPolicyHarness {
    function _hasher() internal pure override returns (address) {
        return address(2);
    }
}
