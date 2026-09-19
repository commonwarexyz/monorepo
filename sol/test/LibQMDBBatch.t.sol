// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.15;

import { LibMerkle } from "../src/merkle/LibMerkle.sol";
import { QMDBTest, ProofKind, RootKind } from "./Common.t.sol";
import { LibQMDBCommon } from "../src/qmdb/LibQMDBCommon.sol";
import { LibQMDBCurrent } from "../src/qmdb/LibQMDBCurrent.sol";
import { LibQMDBAnyMMB } from "../src/qmdb/LibQMDBAnyMMB.sol";
import { LibQMDBAnyMMR } from "../src/qmdb/LibQMDBAnyMMR.sol";
import { LibQMDBKeylessMMB } from "../src/qmdb/LibQMDBKeylessMMB.sol";
import { LibQMDBKeylessMMR } from "../src/qmdb/LibQMDBKeylessMMR.sol";
import { LibQMDBImmutableMMB } from "../src/qmdb/LibQMDBImmutableMMB.sol";
import { LibQMDBImmutableMMR } from "../src/qmdb/LibQMDBImmutableMMR.sol";
import { LibQMDBCurrentMMB } from "../src/qmdb/LibQMDBCurrentMMB.sol";
import { LibQMDBCurrentMMR } from "../src/qmdb/LibQMDBCurrentMMR.sol";

struct BatchCase {
    bytes32 root;
    bytes[] operations;
    LibQMDBCommon.RangeProof range;
    LibQMDBCommon.MultiProof multi;
    ProofKind proofKind;
    RootKind rootKind;
    uint256 chunkBytes;
    LibQMDBCurrent.RangeProof currentRange;
    LibQMDBCurrent.OpsRootWitness witness;
}

struct BatchNode {
    bytes32 digest;
    bytes32 plain;
    uint256 start;
    uint256 width;
    uint256 left;
    uint256 right;
    uint256 selected;
}

enum PlainFacade {
    Any,
    Keyless,
    Immutable
}

abstract contract LibQMDBBatchTest is QMDBTest {
    /// @dev Exercise every plain facade against the same operation bytes and proof.
    function callOperations(BatchCase calldata c, bytes[] memory operations, PlainFacade facade)
        internal
        view
        returns (bool)
    {
        if (c.proofKind == ProofKind.Multi) {
            if (facade == PlainFacade.Any) {
                return _family() == LibMerkle.Family.MMB
                    ? LibQMDBAnyMMB.verifyMulti(c.root, operations, c.multi, _hasher())
                    : LibQMDBAnyMMR.verifyMulti(c.root, operations, c.multi, _hasher());
            }
            if (facade == PlainFacade.Keyless) {
                return _family() == LibMerkle.Family.MMB
                    ? LibQMDBKeylessMMB.verifyMulti(c.root, operations, c.multi, _hasher())
                    : LibQMDBKeylessMMR.verifyMulti(c.root, operations, c.multi, _hasher());
            }
            return _family() == LibMerkle.Family.MMB
                ? LibQMDBImmutableMMB.verifyMulti(c.root, operations, c.multi, _hasher())
                : LibQMDBImmutableMMR.verifyMulti(c.root, operations, c.multi, _hasher());
        }
        if (facade == PlainFacade.Any) {
            return _family() == LibMerkle.Family.MMB
                ? LibQMDBAnyMMB.verifyRange(c.root, operations, c.range, _hasher())
                : LibQMDBAnyMMR.verifyRange(c.root, operations, c.range, _hasher());
        }
        if (facade == PlainFacade.Keyless) {
            return _family() == LibMerkle.Family.MMB
                ? LibQMDBKeylessMMB.verifyRange(c.root, operations, c.range, _hasher())
                : LibQMDBKeylessMMR.verifyRange(c.root, operations, c.range, _hasher());
        }
        return _family() == LibMerkle.Family.MMB
            ? LibQMDBImmutableMMB.verifyRange(c.root, operations, c.range, _hasher())
            : LibQMDBImmutableMMR.verifyRange(c.root, operations, c.range, _hasher());
    }

    /// @dev Authenticate Current range activity or sparse historical inclusion.
    function callCurrent(BatchCase calldata c, bytes[] memory operations) internal view returns (bool) {
        if (c.proofKind == ProofKind.Multi) {
            return _family() == LibMerkle.Family.MMB
                ? LibQMDBCurrentMMB.verifyOpsMulti(c.root, operations, c.multi, c.witness, c.chunkBytes, _hasher())
                : LibQMDBCurrentMMR.verifyOpsMulti(c.root, operations, c.multi, c.witness, c.chunkBytes, _hasher());
        }
        return _family() == LibMerkle.Family.MMB
            ? LibQMDBCurrentMMB.verifyRange(c.root, operations, c.currentRange, c.chunkBytes, _hasher())
            : LibQMDBCurrentMMR.verifyRange(c.root, operations, c.currentRange, c.chunkBytes, _hasher());
    }

    /// @dev Reused caller arrays, the zero slot, and subsequent allocations survive every facade.
    function checked(BatchCase calldata c) external view returns (bool valid) {
        assertTrue(c.proofKind != ProofKind.Single, "range or multi proof required");
        bytes[] memory operations = c.operations;
        bytes memory guard = abi.encode(c);
        bytes32 beforeInputs = keccak256(abi.encode(operations, guard));
        for (uint256 repeat; repeat < (c.rootKind == RootKind.Current ? 2 : 6); ++repeat) {
            uint256 beforePointer;
            uint256 afterPointer;
            uint256 zero;
            assembly ("memory-safe") {
                beforePointer := mload(0x40)
                for { let p := beforePointer } lt(p, add(beforePointer, 0x4000)) { p := add(p, 32) } {
                    mstore(p, not(0))
                }
            }
            bool result = c.rootKind == RootKind.Current
                ? callCurrent(c, operations)
                : callOperations(c, operations, PlainFacade(repeat % 3));
            assembly ("memory-safe") {
                afterPointer := mload(0x40)
                zero := mload(0x60)
            }
            assertGe(afterPointer, beforePointer, "free memory pointer moved backwards");
            assertEq(afterPointer & 31, 0, "unaligned free memory pointer");
            assertEq(zero, 0, "zero slot changed");
            if (repeat != 0) assertEq(result, valid, "facade or repeated verdict differs");
            valid = result;
            bytes memory fresh = new bytes(97);
            for (uint256 i; i < fresh.length; ++i) {
                assertEq(uint8(fresh[i]), 0, "new allocation is dirty");
                fresh[i] = bytes1(uint8(i));
            }
            assertEq(keccak256(abi.encode(operations, guard)), beforeInputs, "caller memory changed");
        }
    }

    /// @dev Materialize append history without using verifier geometry or hashing helpers.
    function operationsCase(uint256 n, uint256[] memory locations, ProofKind proofKind)
        public
        pure
        returns (BatchCase memory c)
    {
        return buildTree(n, locations, proofKind, RootKind.Operations, new bytes32[](0));
    }

    /// @dev Build the selected commitment using 32-byte chunks for Current activity.
    function buildTree(
        uint256 n,
        uint256[] memory locations,
        ProofKind proofKind,
        RootKind rootKind,
        bytes32[] memory chunks
    ) internal pure returns (BatchCase memory c) {
        require(chunks.length == (rootKind == RootKind.Current ? (n + 255) / 256 : 0), "root chunk count");
        c.rootKind = rootKind;
        c.chunkBytes = c.rootKind == RootKind.Current ? 32 : 0;
        c.proofKind = proofKind;
        c.operations = new bytes[](locations.length);
        c.range.leaves = n;
        c.range.start = locations[0];
        c.multi.leaves = n;
        c.multi.locations = locations;
        BatchNode[] memory nodes = new BatchNode[](2 * n);
        uint256[] memory peaks = new uint256[](n);
        uint256 count;
        uint256 position;
        for (uint256 i; i < n; ++i) {
            bytes memory operation = abi.encodePacked(uint32(i), new bytes(i % 34));
            uint256 selected;
            for (uint256 j; j < locations.length; ++j) {
                if (locations[j] == i) {
                    c.operations[j] = operation;
                    selected = 1;
                }
            }
            bytes32 leaf = _hash(abi.encodePacked(uint64(position), operation));
            nodes[position] = BatchNode(leaf, leaf, i, 1, 0, 0, selected);
            peaks[count++] = position++;
            for (uint256 j = count - 1; j > 0; --j) {
                uint256 left = peaks[j - 1];
                uint256 right = peaks[j];
                if (nodes[left].width != nodes[right].width) continue;
                nodes[position] = BatchNode(
                    _hash(abi.encodePacked(uint64(position), nodes[left].digest, nodes[right].digest)),
                    _hash(abi.encodePacked(uint64(position), nodes[left].plain, nodes[right].plain)),
                    nodes[left].start,
                    nodes[left].width * 2,
                    left,
                    right,
                    nodes[left].selected + nodes[right].selected
                );
                if (
                    c.rootKind == RootKind.Current && nodes[position].width == 256
                        && chunks[nodes[position].start / 256] != 0
                ) {
                    nodes[position].digest =
                        _hash(abi.encodePacked(chunks[nodes[position].start / 256], nodes[position].digest));
                }
                peaks[j - 1] = position++;
                for (uint256 k = j; k + 1 < count; ++k) {
                    peaks[k] = peaks[k + 1];
                }
                --count;
                if (_family() == LibMerkle.Family.MMB) break;
                j = count;
            }
        }
        bytes32 folded = nodes[peaks[count - 1]].digest;
        for (uint256 i = count - 1; i > 0; --i) {
            folded = _hash(abi.encodePacked(nodes[peaks[i - 1]].digest, folded));
        }
        c.root = _hash(abi.encodePacked(uint64(n), folded));
        if (c.rootKind == RootKind.Current) {
            c.witness.graftedRoot = c.root;
            bytes32 plain = nodes[peaks[count - 1]].plain;
            for (uint256 i = count - 1; i > 0; --i) {
                plain = _hash(abi.encodePacked(nodes[peaks[i - 1]].plain, plain));
            }
            c.witness.opsRoot = _hash(abi.encodePacked(uint64(n), plain));
            bytes memory input = abi.encodePacked(c.witness.opsRoot, c.witness.graftedRoot);
            uint256 grafted;
            for (uint256 i; i < position; ++i) {
                if (nodes[i].width == 256) ++grafted;
            }
            if (grafted < n / 256) {
                c.witness.pending = _hash(abi.encodePacked(chunks[grafted]));
                input = abi.encodePacked(input, c.witness.pending);
            }
            if (n % 256 != 0) {
                c.witness.partialDigest = _hash(abi.encodePacked(chunks[n / 256]));
                input = abi.encodePacked(input, uint64(n % 256), c.witness.partialDigest);
            }
            c.root = _hash(input);
            if (proofKind == ProofKind.Multi) {
                for (uint256 i; i < position; ++i) {
                    nodes[i].digest = nodes[i].plain;
                }
            }
        }
        if (proofKind == ProofKind.Multi) {
            bool[] memory required = new bool[](position);
            uint256 selectedPeaks;
            for (uint256 i; i < count; ++i) {
                if (nodes[peaks[i]].selected != 0) ++selectedPeaks;
            }
            for (uint256 i; i < count; ++i) {
                uint256 peak = peaks[i];
                required[peak] = nodes[peak].selected == 0 || selectedPeaks > 1;
                markSparse(nodes, peak, required);
            }
            uint256 length;
            for (uint256 i; i < position; ++i) {
                if (required[i]) ++length;
            }
            c.multi.positions = new uint256[](length);
            c.multi.digests = new bytes32[](length);
            length = 0;
            for (uint256 i; i < position; ++i) {
                if (required[i]) {
                    c.multi.positions[length] = i;
                    c.multi.digests[length++] = nodes[i].digest;
                }
            }
        } else {
            bytes32[] memory digests = new bytes32[](position);
            uint256 first;
            uint256 length;
            while (nodes[peaks[first]].selected == 0) digests[length++] = nodes[peaks[first++]].digest;
            uint256 last = count - 1;
            while (nodes[peaks[last]].selected == 0) --last;
            if (last + 1 < count) {
                bytes32 suffix = nodes[peaks[count - 1]].digest;
                for (uint256 i = count - 1; i > last + 1; --i) {
                    suffix = _hash(abi.encodePacked(nodes[peaks[i - 1]].digest, suffix));
                }
                digests[length++] = suffix;
            }
            for (uint256 i = first; i <= last; ++i) {
                length = rangeWitnesses(nodes, peaks[i], digests, length);
            }
            assembly ("memory-safe") { mstore(digests, length) }
            c.range.digests = digests;
            if (c.rootKind == RootKind.Current) {
                c.currentRange.leaves = n;
                c.currentRange.start = locations[0];
                c.currentRange.opsRoot = c.witness.opsRoot;
                c.currentRange.pending = c.witness.pending;
                c.currentRange.partialDigest = c.witness.partialDigest;
                c.currentRange.digests = digests;
                uint256 firstChunk = locations[0] / 256;
                uint256 lastChunk = locations[locations.length - 1] / 256;
                bytes memory packedChunks = new bytes((lastChunk - firstChunk + 1) * 32);
                for (uint256 i = firstChunk; i <= lastChunk; ++i) {
                    bytes32 chunk = chunks[i];
                    assembly ("memory-safe") {
                        mstore(add(add(packedChunks, 32), mul(sub(i, firstChunk), 32)), chunk)
                    }
                }
                c.currentRange.chunks = packedChunks;
            }
        }
    }

    /// @dev Sparse proofs contain the union of physical sibling nodes from the selected leaf paths.
    function markSparse(BatchNode[] memory nodes, uint256 node, bool[] memory required) internal pure {
        BatchNode memory current = nodes[node];
        if (current.width == 1 || current.selected == 0) return;
        required[current.left] = nodes[current.right].selected != 0;
        required[current.right] = nodes[current.left].selected != 0;
        markSparse(nodes, current.left, required);
        markSparse(nodes, current.right, required);
    }

    /// @dev Range witnesses are omitted subtrees in left-to-right traversal order.
    function rangeWitnesses(BatchNode[] memory nodes, uint256 node, bytes32[] memory digests, uint256 length)
        internal
        pure
        returns (uint256)
    {
        BatchNode memory current = nodes[node];
        if (current.selected == 0) {
            digests[length] = current.digest;
            return length + 1;
        }
        if (current.width == 1) return length;
        length = rangeWitnesses(nodes, current.left, digests, length);
        return rangeWitnesses(nodes, current.right, digests, length);
    }

    /// @dev Produce contiguous query locations without imposing an operation encoding.
    function sequence(uint256 start, uint256 count) internal pure returns (uint256[] memory result) {
        result = new uint256[](count);
        for (uint256 i; i < count; ++i) {
            result[i] = start + i;
        }
    }

    /// @dev Small exhaustive intervals independently cover every peak crossing and omitted subtree.
    function test_IndependentSmallRangesAndMultis() public view {
        for (uint256 n = 1; n <= 10; ++n) {
            for (uint256 start; start < n; ++start) {
                for (uint256 count = 1; count <= n - start; ++count) {
                    uint256[] memory selected = sequence(start, count);
                    assertTrue(this.checked(operationsCase(n, selected, ProofKind.Range)), "independent range");
                    assertTrue(this.checked(operationsCase(n, selected, ProofKind.Multi)), "independent multi");
                }
            }
        }
    }

    /// @dev Unsorted sparse queries, equal duplicates, and conflicting duplicates exercise normalization.
    function test_DuplicatesAndUnsortedLocations() public view {
        uint256[] memory selected = new uint256[](4);
        selected[0] = 7;
        selected[1] = 0;
        selected[2] = 3;
        selected[3] = 7;
        BatchCase memory c = operationsCase(9, selected, ProofKind.Multi);
        assertTrue(this.checked(c), "equal duplicate rejected");
        c.operations[3] = hex"bad0";
        assertFalse(this.checked(c), "conflicting duplicate accepted");
    }

    /// @dev Exact witness consumption and all query coordinates are authenticated.
    function rejectMutations(BatchCase memory c) internal view {
        assertTrue(this.checked(c));
        c.root ^= bytes32(uint256(1));
        assertFalse(this.checked(c), "wrong root");
        c.root ^= bytes32(uint256(1));
        bytes memory original = c.operations[0];
        c.operations[0] = abi.encodePacked(original, bytes1(0));
        assertFalse(this.checked(c), "wrong operation length");
        c.operations[0] = original;
        bytes32[] memory witnesses = c.proofKind == ProofKind.Multi ? c.multi.digests : c.range.digests;
        for (uint256 i; i < witnesses.length; ++i) {
            witnesses[i] ^= bytes32(uint256(1));
            assertFalse(this.checked(c), "wrong witness digest");
            witnesses[i] ^= bytes32(uint256(1));
        }
        for (uint256 mode; mode < 2; ++mode) {
            if (mode == 1 && witnesses.length == 0) continue;
            bytes32[] memory changed = new bytes32[](mode == 0 ? witnesses.length + 1 : witnesses.length - 1);
            for (uint256 i; i < changed.length && i < witnesses.length; ++i) {
                changed[i] = witnesses[i];
            }
            if (c.proofKind == ProofKind.Multi) c.multi.digests = changed;
            else c.range.digests = changed;
            assertFalse(this.checked(c), "missing or extra digest");
        }
        if (c.proofKind == ProofKind.Multi) {
            c.multi.digests = witnesses;
            uint256[] memory positions = c.multi.positions;
            for (uint256 mode; mode < 2; ++mode) {
                if (mode == 1 && positions.length == 0) continue;
                uint256 length = mode == 0 ? positions.length + 1 : positions.length - 1;
                c.multi.positions = new uint256[](length);
                c.multi.digests = new bytes32[](length);
                for (uint256 i; i < length && i < positions.length; ++i) {
                    c.multi.positions[i] = positions[i];
                    c.multi.digests[i] = witnesses[i];
                }
                if (mode == 0) c.multi.positions[length - 1] = type(uint256).max;
                assertFalse(this.checked(c), "missing or unused physical witness");
            }
            c.multi.positions = positions;
            c.multi.digests = witnesses;
            for (uint256 i; i < c.multi.positions.length; ++i) {
                uint256 position = c.multi.positions[i];
                c.multi.positions[i] = type(uint256).max;
                assertFalse(this.checked(c), "wrong witness position");
                c.multi.positions[i] = position;
            }
            uint256 inactive = c.multi.inactivePeaks;
            c.multi.inactivePeaks = type(uint256).max;
            assertFalse(this.checked(c), "inactive count");
            c.multi.inactivePeaks = inactive;
            c.multi.locations[0] = c.multi.leaves;
            assertFalse(this.checked(c), "location out of bounds");
            c.multi.locations = new uint256[](0);
            assertFalse(this.checked(c), "mismatched locations");
            c.operations = new bytes[](0);
            assertFalse(this.checked(c), "empty multi");
        } else {
            c.range.digests = witnesses;
            uint256 inactive = c.range.inactivePeaks;
            c.range.inactivePeaks = type(uint256).max;
            assertFalse(this.checked(c), "inactive count");
            c.range.inactivePeaks = inactive;
            c.range.start = c.range.leaves;
            assertFalse(this.checked(c), "range out of bounds");
            c.range.start = type(uint256).max;
            assertFalse(this.checked(c), "overflowing range");
            c.range.start = 0;
            c.operations = new bytes[](0);
            assertFalse(this.checked(c), "empty range");
        }
    }

    /// @dev Mutation checks include witnesses on both sides of a range and selected sparse subtrees.
    function test_BoundsAndWitnessMutations() public view {
        rejectMutations(operationsCase(9, sequence(2, 4), ProofKind.Range));
        rejectMutations(operationsCase(9, sequence(2, 4), ProofKind.Multi));
        for (uint256 mode; mode < 2; ++mode) {
            ProofKind proofKind = mode == 0 ? ProofKind.Range : ProofKind.Multi;
            BatchCase memory c = operationsCase(1, sequence(0, 1), proofKind);
            c.range.leaves = 0;
            c.multi.leaves = 0;
            assertFalse(this.checked(c), "empty tree");
            c.range.leaves = type(uint256).max;
            c.multi.leaves = type(uint256).max;
            assertFalse(this.checked(c), "oversized tree");
        }
    }

    /// @dev Construct mixed activity or all-inactive state without requiring selected operations to be active.
    function currentCase32(uint256 n, uint256 start, uint256 count, ProofKind proofKind, bool zeroChunks)
        internal
        pure
        returns (BatchCase memory)
    {
        bytes32[] memory chunks = new bytes32[]((n + 255) / 256);
        if (!zeroChunks) {
            for (uint256 i; i < n; ++i) {
                if (i % 3 != 0) chunks[i / 256] |= bytes32(uint256(1) << (248 - ((i % 256) / 8) * 8 + i % 8));
            }
        }
        return buildTree(n, sequence(start, count), proofKind, RootKind.Current, chunks);
    }

    /// @dev Current ranges authenticate inactive bits and zero chunks at graft, pending, and partial boundaries.
    function test_CurrentActivityAndBoundaries() public view {
        uint256[10] memory sizes = [uint256(1), 255, 256, 257, 382, 383, 511, 512, 639, 767];
        for (uint256 i; i < sizes.length; ++i) {
            uint256 n = sizes[i];
            uint256 start = n > 256 ? ((n - 1) / 256) * 256 - 1 : 0;
            uint256 count = n - start > 3 ? 3 : n - start;
            for (uint256 mode; mode < 4; ++mode) {
                this.currentBoundary(n, start, count, mode);
            }
        }
    }

    /// @dev Isolate each materialized tree so boundary sweeps reuse EVM memory between cases.
    function currentBoundary(uint256 n, uint256 start, uint256 count, uint256 mode) external view {
        ProofKind proofKind = mode % 2 == 0 ? ProofKind.Range : ProofKind.Multi;
        BatchCase memory c = currentCase32(n, start, count, proofKind, mode < 2);
        assertTrue(this.checked(c), "current activity state");
        if (mode < 2) assertEq(c.witness.graftedRoot, c.witness.opsRoot, "zero graft is not identity");
        rejectCurrentMutations(c);
    }

    /// @dev Current commitment fields and touched chunks bind the same opaque operation batch.
    function rejectCurrentMutations(BatchCase memory c) internal view {
        uint256 chunkBytes = c.chunkBytes;
        uint256[4] memory invalid = [uint256(0), 3, uint256(1) << 60, type(uint256).max];
        for (uint256 i; i < invalid.length; ++i) {
            c.chunkBytes = invalid[i];
            assertFalse(this.checked(c), "invalid chunk configuration");
        }
        c.chunkBytes = chunkBytes;
        bytes32 originalRoot = c.root;
        c.root ^= bytes32(uint256(1));
        assertFalse(this.checked(c), "current root");
        c.root = originalRoot;
        bytes memory original = c.operations[0];
        c.operations[0] = abi.encodePacked(original, bytes1(0));
        assertFalse(this.checked(c), "current operation");
        c.operations[0] = original;
        for (uint256 field; field < 4; ++field) {
            if (field == 0) {
                c.witness.opsRoot ^= bytes32(uint256(1));
                c.currentRange.opsRoot ^= bytes32(uint256(1));
            }
            if (field == 1) c.witness.graftedRoot ^= bytes32(uint256(1));
            if (field == 2) {
                c.witness.pending ^= bytes32(uint256(1));
                c.currentRange.pending ^= bytes32(uint256(1));
            }
            if (field == 3) {
                c.witness.partialDigest ^= bytes32(uint256(1));
                c.currentRange.partialDigest ^= bytes32(uint256(1));
            }
            if (field != 1 || c.proofKind == ProofKind.Multi) {
                assertFalse(this.checked(c), "current commitment witness");
            }
            if (field == 0) {
                c.witness.opsRoot ^= bytes32(uint256(1));
                c.currentRange.opsRoot ^= bytes32(uint256(1));
            }
            if (field == 1) c.witness.graftedRoot ^= bytes32(uint256(1));
            if (field == 2) {
                c.witness.pending ^= bytes32(uint256(1));
                c.currentRange.pending ^= bytes32(uint256(1));
            }
            if (field == 3) {
                c.witness.partialDigest ^= bytes32(uint256(1));
                c.currentRange.partialDigest ^= bytes32(uint256(1));
            }
        }
        if (c.proofKind == ProofKind.Multi) {
            rejectMutations(c);
        } else {
            uint256 originalStart = c.currentRange.start;
            c.currentRange.start = type(uint256).max;
            assertFalse(this.checked(c), "current range bounds");
            c.currentRange.start = originalStart;
            bytes32[] memory digests = c.currentRange.digests;
            for (uint256 i; i < digests.length; ++i) {
                digests[i] ^= bytes32(uint256(1));
                assertFalse(this.checked(c), "current range witness");
                digests[i] ^= bytes32(uint256(1));
            }
            c.currentRange.digests = new bytes32[](digests.length + 1);
            for (uint256 i; i < digests.length; ++i) {
                c.currentRange.digests[i] = digests[i];
            }
            assertFalse(this.checked(c), "current extra witness");
            if (digests.length != 0) {
                c.currentRange.digests = new bytes32[](digests.length - 1);
                for (uint256 i; i < c.currentRange.digests.length; ++i) {
                    c.currentRange.digests[i] = digests[i];
                }
                assertFalse(this.checked(c), "current missing witness");
            }
            c.currentRange.digests = digests;
            for (uint256 i; i < c.currentRange.chunks.length; i += c.chunkBytes) {
                c.currentRange.chunks[i] ^= 0x01;
                assertFalse(this.checked(c), "current chunk");
                c.currentRange.chunks[i] ^= 0x01;
            }
            bytes memory originalChunks = c.currentRange.chunks;
            c.currentRange.chunks = new bytes(originalChunks.length - 1);
            for (uint256 i; i < c.currentRange.chunks.length; ++i) {
                c.currentRange.chunks[i] = originalChunks[i];
            }
            assertFalse(this.checked(c), "nonintegral short chunks");
            c.currentRange.chunks = new bytes(originalChunks.length + 1);
            for (uint256 i; i < originalChunks.length; ++i) {
                c.currentRange.chunks[i] = originalChunks[i];
            }
            assertFalse(this.checked(c), "nonintegral long chunks");
            c.currentRange.chunks = new bytes(originalChunks.length + c.chunkBytes);
            for (uint256 i; i < originalChunks.length; ++i) {
                c.currentRange.chunks[i] = originalChunks[i];
            }
            assertFalse(this.checked(c), "extra chunk");
            c.currentRange.chunks = new bytes(originalChunks.length - c.chunkBytes);
            for (uint256 i; i < c.currentRange.chunks.length; ++i) {
                c.currentRange.chunks[i] = originalChunks[i];
            }
            assertFalse(this.checked(c), "missing chunk");
        }
    }

    /// @dev Decode operations or Current batch proofs from the Rust oracle.
    function generate(
        uint256 n,
        uint256[] memory selected,
        uint256 floor,
        ProofKind proofKind,
        RootKind rootKind,
        string memory variant,
        string memory activity,
        uint256 chunkBytes,
        string memory encoding
    ) internal returns (BatchCase memory c) {
        string[] memory args = new string[](
            (proofKind == ProofKind.Multi ? 19 : 21) + (rootKind == RootKind.Current ? 4 : 0)
        );
        args[0] = string.concat(vm.projectRoot(), "/../target/release/commonware-sol-fuzz");
        args[1] = "qmdb";
        args[2] = proofKind == ProofKind.Multi ? "multi" : "range";
        args[3] = "--leaves";
        args[4] = vm.toString(n);
        uint256 offset = 5;
        if (proofKind == ProofKind.Multi) {
            args[offset++] = "--locations";
            args[offset] = vm.toString(selected[0]);
            for (uint256 i = 1; i < selected.length; ++i) {
                args[offset] = string.concat(args[offset], ",", vm.toString(selected[i]));
            }
            ++offset;
        } else {
            args[offset++] = "--start";
            args[offset++] = vm.toString(selected[0]);
            args[offset++] = "--count";
            args[offset++] = vm.toString(selected.length);
        }
        args[offset++] = "--seed";
        args[offset++] = "71";
        args[offset++] = "--family";
        args[offset++] = _family() == LibMerkle.Family.MMB ? "mmb" : "mmr";
        args[offset++] = "--variant";
        args[offset++] = variant;
        args[offset++] = "--encoding";
        args[offset++] = encoding;
        args[offset++] = "--inactivity-floor";
        args[offset++] = vm.toString(floor);
        if (rootKind == RootKind.Current) {
            args[offset++] = "--activity";
            args[offset++] = activity;
            args[offset++] = "--chunk-bytes";
            args[offset++] = vm.toString(chunkBytes);
        } else {
            assertEq(bytes(activity).length, 0, "operations roots have no activity policy");
            assertEq(chunkBytes, 0, "operations roots have no activity chunks");
        }
        args[offset++] = "--root";
        args[offset] = rootKind == RootKind.Operations ? "operations" : "current";
        c.proofKind = proofKind;
        c.rootKind = rootKind;
        c.chunkBytes = chunkBytes;
        bytes memory output = _ffi(args);
        if (rootKind == RootKind.Current && proofKind == ProofKind.Multi) {
            (
                c.root,
                c.multi.leaves,
                c.multi.locations,
                c.multi.inactivePeaks,
                c.multi.positions,
                c.multi.digests,
                c.operations,
                c.witness.opsRoot,
                c.witness.graftedRoot,
                c.witness.pending,
                c.witness.partialDigest
            ) =
                abi.decode(
                    output,
                    (
                        bytes32,
                        uint256,
                        uint256[],
                        uint256,
                        uint256[],
                        bytes32[],
                        bytes[],
                        bytes32,
                        bytes32,
                        bytes32,
                        bytes32
                    )
                );
        } else if (rootKind == RootKind.Current) {
            (
                c.root,
                c.currentRange.leaves,
                c.currentRange.start,
                c.currentRange.inactivePeaks,
                c.currentRange.digests,
                c.operations,
                c.currentRange.chunks,
                c.currentRange.opsRoot,
                c.currentRange.pending,
                c.currentRange.partialDigest
            ) =
                abi.decode(
                    output, (bytes32, uint256, uint256, uint256, bytes32[], bytes[], bytes, bytes32, bytes32, bytes32)
                );
        } else if (proofKind == ProofKind.Multi) {
            (
                c.root,
                c.multi.leaves,
                c.multi.locations,
                c.multi.inactivePeaks,
                c.multi.positions,
                c.multi.digests,
                c.operations
            ) = abi.decode(output, (bytes32, uint256, uint256[], uint256, uint256[], bytes32[], bytes[]));
        } else {
            (c.root, c.range.leaves, c.range.start, c.range.inactivePeaks, c.range.digests, c.operations) =
                abi.decode(output, (bytes32, uint256, uint256, uint256, bytes32[], bytes[]));
        }
    }

    /// @dev Every production operation codec shares plain batch authentication and exact witness checks.
    function test_DifferentialOperationVariantsAndInactivePeaks() public {
        string[4] memory variants = [string("ordered"), "unordered", "keyless", "immutable"];
        for (uint256 i; i < variants.length; ++i) {
            for (uint256 mode; mode < 2; ++mode) {
                ProofKind proofKind = mode == 0 ? ProofKind.Range : ProofKind.Multi;
                BatchCase memory c = generate(
                    1023, sequence(768, 3), 768, proofKind, RootKind.Operations, variants[i], "", 0, "fixed"
                );
                assertGt(mode == 0 ? c.range.inactivePeaks : c.multi.inactivePeaks, 0, "inactive fixture");
                rejectMutations(c);
            }
        }
    }

    /// @dev Variable operation codecs authenticate values across word and varint length boundaries.
    function test_DifferentialVariableOperationCodecs() public {
        string[4] memory variants = [string("ordered"), "unordered", "keyless", "immutable"];
        uint256[8] memory lengths = [uint256(129), 0, 1, 31, 32, 33, 127, 128];
        for (uint256 i; i < variants.length; ++i) {
            for (uint256 mode; mode < (i < 2 ? 4 : 2); ++mode) {
                BatchCase memory c = generate(
                    17,
                    sequence(0, 8),
                    0,
                    mode % 2 == 0 ? ProofKind.Range : ProofKind.Multi,
                    mode >= 2 ? RootKind.Current : RootKind.Operations,
                    variants[i],
                    mode >= 2 ? "mixed" : "",
                    mode >= 2 ? 1 : 0,
                    "variable"
                );
                uint256 overhead = i == 0 ? 65 : i == 2 ? 1 : 33;
                for (uint256 j; j < lengths.length; ++j) {
                    assertEq(c.operations[j].length, overhead + lengths[j] + (lengths[j] < 128 ? 1 : 2));
                }
                assertTrue(this.checked(c), "variable codec batch");
                if (c.rootKind == RootKind.Current) rejectCurrentMutations(c);
                else rejectMutations(c);
            }
        }
    }

    /// @dev Rust Current proofs cover inactive chunks, mixed bits, and pending plus partial commitments.
    function test_DifferentialCurrentBoundaries() public {
        uint256[6] memory sizes = [uint256(256), 257, 383, 512, 639, 1023];
        for (uint256 i; i < sizes.length; ++i) {
            uint256 n = sizes[i];
            uint256 start = n > 256 ? ((n - 1) / 256) * 256 - 1 : 0;
            uint256 count = n - start > 3 ? 3 : n - start;
            for (uint256 mode; mode < 4; ++mode) {
                BatchCase memory c = generate(
                    n,
                    sequence(start, count),
                    0,
                    mode % 2 == 0 ? ProofKind.Range : ProofKind.Multi,
                    RootKind.Current,
                    "unordered",
                    mode < 2 ? "zero" : "mixed",
                    32,
                    "fixed"
                );
                assertTrue(this.checked(c), "Rust Current disagreement");
                rejectCurrentMutations(c);
            }
        }
    }

    /// @dev Packed zero chunks and sparse historical operations verify at every supported chunk size.
    function test_DifferentialVariableCurrentBatches() public {
        uint256[6] memory sizes = [uint256(1), 2, 16, 32, 64, 128];
        for (uint256 i; i < sizes.length; ++i) {
            uint256 chunkBytes = sizes[i];
            uint256 chunkBits = chunkBytes * 8;
            uint256 n = 2 * chunkBits + 1;
            BatchCase memory range = generate(
                n,
                sequence(chunkBits - 1, 3),
                0,
                ProofKind.Range,
                RootKind.Current,
                "unordered",
                "zero",
                chunkBytes,
                "fixed"
            );
            assertEq(range.currentRange.chunks.length, 2 * chunkBytes, "packed touched chunks");
            assertTrue(this.checked(range), "variable Current range");
            rejectCurrentMutations(range);

            BatchCase memory mixed = generate(
                n,
                sequence(chunkBits - 1, 3),
                0,
                ProofKind.Range,
                RootKind.Current,
                "unordered",
                "mixed",
                chunkBytes,
                "fixed"
            );
            assertTrue(this.checked(mixed), "variable mixed Current range");
            BatchCase memory active = generate(
                n,
                sequence(chunkBits - 1, 3),
                0,
                ProofKind.Range,
                RootKind.Current,
                "unordered",
                "all",
                chunkBytes,
                "fixed"
            );
            assertTrue(this.checked(active), "variable active Current range");
            if (chunkBytes > 32) {
                uint256 last = active.currentRange.chunks.length - 1;
                active.currentRange.chunks[last] ^= 0x01;
                assertFalse(this.checked(active), "large chunk last byte");
            }

            uint256[] memory selected = new uint256[](3);
            selected[0] = n - 1;
            selected[1] = 0;
            selected[2] = chunkBits;
            BatchCase memory historical =
                generate(n, selected, 0, ProofKind.Multi, RootKind.Current, "unordered", "zero", chunkBytes, "fixed");
            assertTrue(this.checked(historical), "variable historical operation witness");
            rejectCurrentMutations(historical);
        }
    }

    /// @dev Operation and grafted trees authenticate their own inactive peak boundaries.
    function test_DifferentialSeparateInactiveCounts() public {
        uint256[] memory selected = sequence(896, 1);
        BatchCase memory range =
            generate(1023, selected, 896, ProofKind.Range, RootKind.Current, "unordered", "all", 32, "fixed");
        BatchCase memory multi =
            generate(1023, selected, 896, ProofKind.Multi, RootKind.Current, "unordered", "all", 32, "fixed");
        assertEq(range.root, multi.root);
        assertTrue(range.currentRange.inactivePeaks != multi.multi.inactivePeaks);
        assertTrue(this.checked(range));
        assertTrue(this.checked(multi));
        uint256 rangeInactive = range.currentRange.inactivePeaks;
        range.currentRange.inactivePeaks = multi.multi.inactivePeaks;
        multi.multi.inactivePeaks = rangeInactive;
        assertFalse(this.checked(range));
        assertFalse(this.checked(multi));
    }

    /// @dev Random floors and caller order compare batch core paths with Rust and reject altered operations.
    function testFuzz_DifferentialBatches(uint16 sizeSeed, uint16 querySeed, uint16 floorSeed, uint8 mode) public {
        uint256 n = uint256(sizeSeed) % 1536 + 1;
        uint256 floor = uint256(floorSeed) % n;
        uint256 start = floor + uint256(querySeed) % (n - floor);
        uint256 count = n - start > 5 ? 5 : n - start;
        ProofKind proofKind = mode % 2 == 0 ? ProofKind.Range : ProofKind.Multi;
        RootKind rootKind = mode % 4 >= 2 ? RootKind.Current : RootKind.Operations;
        uint256[] memory selected = sequence(start, count);
        if (proofKind == ProofKind.Multi) {
            for (uint256 i; i < count; ++i) {
                selected[i] = floor + uint256(keccak256(abi.encode(querySeed, i))) % (n - floor);
            }
        }
        BatchCase memory c = generate(
            n,
            selected,
            floor,
            proofKind,
            rootKind,
            "ordered",
            rootKind == RootKind.Operations ? "" : mode % 8 < 4 ? "mixed" : "zero",
            rootKind == RootKind.Current ? 32 : 0,
            "fixed"
        );
        assertTrue(this.checked(c), "Rust batch disagreement");
        c.operations[0] = abi.encodePacked(c.operations[0], bytes1(0));
        assertFalse(this.checked(c), "modified Rust operation");
    }

    /// @dev Random contiguous and scattered selections compare reconstruction with an independent tree.
    function testFuzz_IndependentBatches(uint16 sizeSeed, uint16 startSeed, uint16 countSeed, uint8 proofSeed)
        public
        view
    {
        uint256 n = uint256(sizeSeed) % 96 + 1;
        uint256 start = uint256(startSeed) % n;
        uint256 count = uint256(countSeed) % (n - start) + 1;
        ProofKind proofKind = proofSeed % 2 == 0 ? ProofKind.Range : ProofKind.Multi;
        uint256[] memory selected = sequence(start, count);
        if (proofKind == ProofKind.Multi) {
            for (uint256 i; i < count; ++i) {
                selected[i] = uint256(keccak256(abi.encode(startSeed, i))) % n;
            }
        }
        BatchCase memory c = operationsCase(n, selected, proofKind);
        assertTrue(this.checked(c));
        c.operations[0] = abi.encodePacked(c.operations[0], bytes1(0));
        assertFalse(this.checked(c), "mutated batch accepted");
    }
}

abstract contract LibQMDBBatchMMBTest is LibQMDBBatchTest {
    function _family() internal pure override returns (LibMerkle.Family) {
        return LibMerkle.Family.MMB;
    }
}

contract LibQMDBBatchMMBKeccak256Test is LibQMDBBatchMMBTest {
    function _hasher() internal pure override returns (address) {
        return address(0);
    }
}

contract LibQMDBBatchMMBSha256Test is LibQMDBBatchMMBTest {
    function _hasher() internal pure override returns (address) {
        return address(2);
    }
}

abstract contract LibQMDBBatchMMRTest is LibQMDBBatchTest {
    function _family() internal pure override returns (LibMerkle.Family) {
        return LibMerkle.Family.MMR;
    }
}

contract LibQMDBBatchMMRKeccak256Test is LibQMDBBatchMMRTest {
    function _hasher() internal pure override returns (address) {
        return address(0);
    }
}

contract LibQMDBBatchMMRSha256Test is LibQMDBBatchMMRTest {
    function _hasher() internal pure override returns (address) {
        return address(2);
    }
}
