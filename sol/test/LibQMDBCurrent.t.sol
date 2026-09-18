// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.15;

import { UnorderedOracle } from "./Common.t.sol";
import { Current } from "../src/qmdb/Current.sol";
import { LibQMDBCurrentMMB } from "../src/qmdb/LibQMDBCurrentMMB.sol";
import { LibQMDBCurrentMMR } from "../src/qmdb/LibQMDBCurrentMMR.sol";

/// @dev Operations remain opaque byte strings.
struct QMDBCase {
    bytes32 root;
    bytes operation;
    uint256 chunkBytes;
    Current.Proof proof;
}

/// @dev Append history supplies positions and ancestry independently of verifier geometry.
struct QMDBNode {
    bytes32 digest;
    bytes32 plain;
    uint256 start;
    uint256 width;
    uint256 left;
    uint256 right;
}

contract LibQMDBCurrentTest is UnorderedOracle {
    /// @dev Select the delayed-merge MMB append family.
    function _mmb() internal pure virtual override returns (bool) {
        return true;
    }

    /// @dev Expose the calldata proof entrypoint for tests and gas measurements.
    function verify(QMDBCase calldata c) external view returns (bool) {
        return _mmb()
            ? LibQMDBCurrentMMB.verify(c.root, c.operation, c.proof, c.chunkBytes, _hasher())
            : LibQMDBCurrentMMR.verify(c.root, c.operation, c.proof, c.chunkBytes, _hasher());
    }

    /// @dev Expose the default configuration as a literal for comparable gas measurements.
    function verify32(QMDBCase calldata c) external view returns (bool) {
        return _mmb()
            ? LibQMDBCurrentMMB.verify(c.root, c.operation, c.proof, 32, _hasher())
            : LibQMDBCurrentMMR.verify(c.root, c.operation, c.proof, 32, _hasher());
    }

    /// @dev Reject the supplied root and proof under the other append family's topology.
    function rejectOtherFamily(QMDBCase calldata c) external view {
        bool valid = _mmb()
            ? LibQMDBCurrentMMR.verify(c.root, c.operation, c.proof, c.chunkBytes, _hasher())
            : LibQMDBCurrentMMB.verify(c.root, c.operation, c.proof, c.chunkBytes, _hasher());
        assertFalse(valid, "proof accepted by the other append family");
    }

    /// @dev Check caller allocations, dirty scratch, and subsequent allocations on every exit path.
    function checked(QMDBCase calldata c) external view returns (bool) {
        return _checked(c, 0, hex"", Current.ExclusionEncoding(0, 0));
    }

    /// @dev Exercise exclusion with the same caller-memory checks as membership.
    function checkedExclusion(QMDBCase calldata c, bytes32 key) external view returns (bool) {
        return _checked(c, 1, abi.encodePacked(key), Current.ExclusionEncoding(0, 0));
    }

    /// @dev Repeated verification preserves inputs and leaves subsequent allocations zeroed.
    function _checked(QMDBCase calldata c, uint256 mode, bytes memory key, Current.ExclusionEncoding memory encoding)
        internal
        view
        returns (bool valid)
    {
        bytes memory operation = c.operation;
        bytes memory guard = abi.encode(c);
        bytes32 beforeInputs = keccak256(abi.encode(operation, guard, key, encoding));
        for (uint256 repeat; repeat < 2; ++repeat) {
            uint256 beforePointer;
            uint256 afterPointer;
            uint256 zero;
            assembly ("memory-safe") {
                beforePointer := mload(0x40)
                for { let p := beforePointer } lt(p, add(beforePointer, 0x2000)) { p := add(p, 32) } {
                    mstore(p, not(0))
                }
            }
            bool result;
            if (mode == 2) {
                result = _mmb()
                    ? LibQMDBCurrentMMB.verifyExclusionVariable(
                        c.root, key, operation, c.proof, encoding, c.chunkBytes, _hasher()
                    )
                    : LibQMDBCurrentMMR.verifyExclusionVariable(
                        c.root, key, operation, c.proof, encoding, c.chunkBytes, _hasher()
                    );
            } else if (mode == 1) {
                result = _mmb()
                    ? LibQMDBCurrentMMB.verifyExclusion(
                        c.root, bytes32(key), operation, c.proof, c.chunkBytes, _hasher()
                    )
                    : LibQMDBCurrentMMR.verifyExclusion(
                        c.root, bytes32(key), operation, c.proof, c.chunkBytes, _hasher()
                    );
            } else {
                result = _mmb()
                    ? LibQMDBCurrentMMB.verify(c.root, operation, c.proof, c.chunkBytes, _hasher())
                    : LibQMDBCurrentMMR.verify(c.root, operation, c.proof, c.chunkBytes, _hasher());
            }
            assembly ("memory-safe") {
                afterPointer := mload(0x40)
                zero := mload(0x60)
            }
            assertGe(afterPointer, beforePointer, "free memory pointer moved backwards");
            assertEq(afterPointer & 31, 0, "unaligned free memory pointer");
            assertEq(zero, 0, "zero slot changed");
            if (repeat != 0) assertEq(result, valid, "repeated result changed");
            valid = result;
            bytes memory fresh = new bytes(97);
            for (uint256 i; i < fresh.length; ++i) {
                assertEq(uint8(fresh[i]), 0, "new allocation is dirty");
                fresh[i] = bytes1(uint8(i));
            }
            assertEq(keccak256(abi.encode(operation, guard, key, encoding)), beforeInputs, "caller memory changed");
        }
    }

    /// @dev Replay family-specific append merges using the default 32-byte bitmap chunks.
    function build(uint256 n, uint256 location, bytes memory operation, bool active)
        external
        pure
        returns (QMDBCase memory c)
    {
        return _build(n, location, operation, active, 32);
    }

    /// @dev Replay append history with a caller-selected bitmap chunk size.
    function buildChunk(uint256 n, uint256 location, bytes memory operation, bool active, uint256 chunkBytes)
        external
        pure
        returns (QMDBCase memory c)
    {
        return _build(n, location, operation, active, chunkBytes);
    }

    /// @dev Build an independent proof using `chunkBytes * 8` activity bits per graft.
    function _build(uint256 n, uint256 location, bytes memory operation, bool active, uint256 chunkBytes)
        internal
        pure
        returns (QMDBCase memory c)
    {
        c.operation = operation;
        c.chunkBytes = chunkBytes;
        c.proof.leaves = n;
        c.proof.location = location;
        uint256 chunkBits = chunkBytes * 8;
        bytes[] memory chunks = new bytes[]((n + chunkBits - 1) / chunkBits);
        for (uint256 i; i < chunks.length; ++i) {
            chunks[i] = new bytes(chunkBytes);
        }
        for (uint256 i; i < n; ++i) {
            if (i == location ? active : i % 3 != 0) {
                uint256 bit = i % chunkBits;
                chunks[i / chunkBits][bit >> 3] |= bytes1(uint8(1 << (bit & 7)));
            }
        }
        c.proof.chunk = chunks[location / chunkBits];
        QMDBNode[] memory nodes = new QMDBNode[](2 * n);
        uint256[] memory peaks = new uint256[](n);
        uint256 count;
        uint256 position;
        for (uint256 i; i < n; ++i) {
            bytes memory encoded = i == location ? operation : abi.encodePacked(uint32(i), bytes1(0xa5));
            bytes32 leaf = _hash(abi.encodePacked(uint64(position), encoded));
            nodes[position] = QMDBNode(leaf, leaf, i, 1, 0, 0);
            peaks[count++] = position++;
            for (uint256 j = count - 1; j > 0; --j) {
                uint256 left = peaks[j - 1];
                uint256 right = peaks[j];
                if (nodes[left].width != nodes[right].width) continue;
                QMDBNode memory parent;
                parent.start = nodes[left].start;
                parent.width = nodes[left].width * 2;
                parent.left = left;
                parent.right = right;
                parent.plain = _hash(abi.encodePacked(uint64(position), nodes[left].plain, nodes[right].plain));
                parent.digest = _hash(abi.encodePacked(uint64(position), nodes[left].digest, nodes[right].digest));
                if (parent.width == chunkBits) {
                    parent.digest = _hash(abi.encodePacked(chunks[parent.start / chunkBits], parent.digest));
                }
                nodes[position] = parent;
                peaks[j - 1] = position++;
                for (uint256 k = j; k + 1 < count; ++k) {
                    peaks[k] = peaks[k + 1];
                }
                --count;
                if (_mmb()) break;
                j = count;
            }
        }
        bytes32 plain = nodes[peaks[count - 1]].plain;
        bytes32 grafted = nodes[peaks[count - 1]].digest;
        for (uint256 i = count - 1; i > 0; --i) {
            plain = _hash(abi.encodePacked(nodes[peaks[i - 1]].plain, plain));
            grafted = _hash(abi.encodePacked(nodes[peaks[i - 1]].digest, grafted));
        }
        c.proof.opsRoot = _hash(abi.encodePacked(uint64(n), plain));
        bytes memory rootInput = abi.encodePacked(c.proof.opsRoot, _hash(abi.encodePacked(uint64(n), grafted)));
        uint256 graftedChunks;
        for (uint256 i; i < position; ++i) {
            if (nodes[i].width == chunkBits) ++graftedChunks;
        }
        if (graftedChunks < n / chunkBits) {
            c.proof.pending = _hash(abi.encodePacked(chunks[graftedChunks]));
            rootInput = abi.encodePacked(rootInput, c.proof.pending);
        }
        if (n % chunkBits != 0) {
            c.proof.partialDigest = _hash(abi.encodePacked(chunks[n / chunkBits]));
            rootInput = abi.encodePacked(rootInput, uint64(n % chunkBits), c.proof.partialDigest);
        }
        c.root = _hash(rootInput);
        bytes32[] memory digests = new bytes32[](count + 64);
        uint256 length;
        uint256 target;
        while (location >= nodes[peaks[target]].start + nodes[peaks[target]].width) {
            digests[length++] = nodes[peaks[target++]].digest;
        }
        if (target + 1 < count) {
            bytes32 suffix = nodes[peaks[count - 1]].digest;
            for (uint256 i = count - 1; i > target + 1; --i) {
                suffix = _hash(abi.encodePacked(nodes[peaks[i - 1]].digest, suffix));
            }
            digests[length++] = suffix;
        }
        length = witnesses(nodes, peaks[target], location, digests, length);
        assembly ("memory-safe") { mstore(digests, length) }
        c.proof.digests = digests;
    }

    /// @dev Emit omitted children in left-first traversal order from the materialized tree.
    function witnesses(
        QMDBNode[] memory nodes,
        uint256 node,
        uint256 location,
        bytes32[] memory digests,
        uint256 length
    ) internal pure returns (uint256) {
        QMDBNode memory current = nodes[node];
        if (current.width == 1) return length;
        if (location < nodes[current.right].start) {
            length = witnesses(nodes, current.left, location, digests, length);
            digests[length++] = nodes[current.right].digest;
        } else {
            digests[length++] = nodes[current.left].digest;
            length = witnesses(nodes, current.right, location, digests, length);
        }
        return length;
    }

    /// @dev Cover chunk completion, delayed graft creation, and higher grafted ancestors.
    function test_IndependentBoundaryTrees() public view {
        uint256[16] memory sizes =
            [uint256(1), 2, 255, 256, 257, 382, 383, 511, 512, 513, 638, 639, 767, 1023, 1535, 2047];
        for (uint256 i; i < sizes.length; ++i) {
            uint256 n = sizes[i];
            uint256[4] memory locations = [uint256(0), n / 2, n > 256 ? 255 : n - 1, n - 1];
            for (uint256 j; j < locations.length; ++j) {
                QMDBCase memory c = this.build(n, locations[j], hex"00112233445566778899aabbcc", true);
                if (!_mmb()) assertEq(c.proof.pending, 0, "MMR leaves a complete chunk ungrafted");
                assertTrue(this.checked(c));
            }
        }
    }

    /// @dev An operation is an opaque byte string, including empty and non-word-aligned encodings.
    function testFuzz_ArbitraryOperation(bytes memory operation, uint16 seed) public view {
        uint256 n = uint256(seed) % 640 + 1;
        QMDBCase memory c = this.build(n, uint256(seed) % n, operation, true);
        assertTrue(this.checked(c));
        c.operation = abi.encodePacked(operation, bytes1(0));
        assertFalse(this.checked(c), "operation length is not bound");
    }

    /// @dev Empty and word-boundary operation lengths preserve positioned hashing and caller memory.
    function test_OperationLengths() public view {
        uint256[9] memory lengths = [uint256(0), 1, 31, 32, 33, 64, 65, 97, 257];
        for (uint256 i; i < lengths.length; ++i) {
            bytes memory operation = new bytes(lengths[i]);
            for (uint256 j; j < operation.length; ++j) {
                operation[j] = bytes1(uint8(j));
            }
            assertTrue(this.checked(this.build(383, 127, operation, true)));
        }
    }

    /// @dev Each bit within a byte uses LSB order, including both ends of a chunk.
    function test_BitmapBitOrder() public view {
        uint256[10] memory locations = [uint256(0), 1, 2, 3, 4, 5, 6, 7, 248, 255];
        for (uint256 i; i < locations.length; ++i) {
            QMDBCase memory c = this.build(383, locations[i], hex"00", true);
            assertTrue(this.verify(c));
            c = this.build(383, locations[i], hex"00", false);
            assertFalse(this.checked(c), "authenticated inactive operation accepted");
        }
    }

    /// @dev Variable chunks authenticate both endpoint bits across complete and partial boundaries.
    function test_VariableChunkBoundaries() public view {
        uint256[6] memory sizes = [uint256(1), 2, 16, 32, 64, 128];
        for (uint256 i; i < sizes.length; ++i) {
            uint256 chunkBytes = sizes[i];
            uint256 chunkBits = chunkBytes * 8;
            uint256[5] memory leaves = [
                chunkBits + chunkBits / 2 - 2,
                chunkBits + chunkBits / 2 - 1,
                chunkBits,
                chunkBits + 1,
                2 * chunkBits + 1
            ];
            for (uint256 j; j < leaves.length; ++j) {
                uint256 n = leaves[j];
                assertTrue(this.checked(this.buildChunk(n, 0, hex"00", true, chunkBytes)));
                assertTrue(this.checked(this.buildChunk(n, n - 1, hex"01", true, chunkBytes)));
            }
        }
    }

    /// @dev Reject invalid chunk configurations and singleton payload lengths before reconstruction.
    function test_MalformedChunkConfigurationAndLength() public view {
        QMDBCase memory c = this.buildChunk(33, 32, hex"0102", true, 2);
        assertTrue(this.checked(c));
        uint256 valid = c.chunkBytes;
        uint256[4] memory invalid = [uint256(0), 3, uint256(1) << 60, type(uint256).max];
        for (uint256 i; i < invalid.length; ++i) {
            c.chunkBytes = invalid[i];
            assertFalse(this.checked(c), "invalid chunk configuration");
        }
        c.chunkBytes = valid;
        bytes memory chunk = c.proof.chunk;
        c.proof.chunk = new bytes(chunk.length - 1);
        for (uint256 i; i < c.proof.chunk.length; ++i) {
            c.proof.chunk[i] = chunk[i];
        }
        assertFalse(this.checked(c), "short chunk");
        c.proof.chunk = new bytes(chunk.length + 1);
        for (uint256 i; i < chunk.length; ++i) {
            c.proof.chunk[i] = chunk[i];
        }
        assertFalse(this.checked(c), "long chunk");
    }

    /// @dev Fixed-schema exclusion remains independent of the authenticated bitmap chunk size.
    function test_VariableChunkFixedSchemaExclusion() public view {
        bytes memory operation = abi.encodePacked(bytes1(0xd2), bytes32(uint256(10)), hex"112233", bytes32(uint256(20)));
        uint256[6] memory sizes = [uint256(1), 2, 16, 32, 64, 128];
        for (uint256 i; i < sizes.length; ++i) {
            QMDBCase memory c = this.buildChunk(17, 16, operation, true, sizes[i]);
            assertTrue(this.checkedExclusion(c, bytes32(uint256(15))));
            assertFalse(this.checkedExclusion(c, bytes32(uint256(10))));
        }
    }

    /// @dev Every supplied commitment, sibling, and coordinate is authenticated.
    function rejectMutations(QMDBCase memory c) internal view {
        rejectMutations(c, false, 0);
    }

    /// @dev Apply proof mutations to either verifier while keeping the exclusion query fixed.
    function rejectMutations(QMDBCase memory c, bool exclusion, bytes32 key) internal view {
        assertTrue(exclusion ? this.checkedExclusion(c, key) : this.checked(c));
        c.root ^= bytes32(uint256(1));
        assertFalse(exclusion ? this.checkedExclusion(c, key) : this.checked(c));
        c.root ^= bytes32(uint256(1));
        c.proof.opsRoot ^= bytes32(uint256(1));
        assertFalse(exclusion ? this.checkedExclusion(c, key) : this.checked(c));
        c.proof.opsRoot ^= bytes32(uint256(1));
        c.proof.pending ^= bytes32(uint256(1));
        assertFalse(exclusion ? this.checkedExclusion(c, key) : this.checked(c));
        c.proof.pending ^= bytes32(uint256(1));
        c.proof.partialDigest ^= bytes32(uint256(1));
        assertFalse(exclusion ? this.checkedExclusion(c, key) : this.checked(c));
        c.proof.partialDigest ^= bytes32(uint256(1));
        c.proof.chunk[c.proof.chunk.length / 2] ^= 0x01;
        assertFalse(exclusion ? this.checkedExclusion(c, key) : this.checked(c));
        c.proof.chunk[c.proof.chunk.length / 2] ^= 0x01;
        uint256 inactive = c.proof.inactivePeaks;
        c.proof.inactivePeaks = type(uint256).max;
        assertFalse(exclusion ? this.checkedExclusion(c, key) : this.checked(c));
        c.proof.inactivePeaks = inactive;
        for (uint256 i; i < c.proof.digests.length; ++i) {
            c.proof.digests[i] ^= bytes32(uint256(1));
            assertFalse(exclusion ? this.checkedExclusion(c, key) : this.checked(c));
            c.proof.digests[i] ^= bytes32(uint256(1));
        }
        bytes32[] memory original = c.proof.digests;
        c.proof.digests = new bytes32[](original.length + 1);
        for (uint256 i; i < original.length; ++i) {
            c.proof.digests[i] = original[i];
        }
        assertFalse(exclusion ? this.checkedExclusion(c, key) : this.checked(c), "trailing witness accepted");
        if (original.length != 0) {
            c.proof.digests = new bytes32[](original.length - 1);
            for (uint256 i; i < c.proof.digests.length; ++i) {
                c.proof.digests[i] = original[i];
            }
            assertFalse(exclusion ? this.checkedExclusion(c, key) : this.checked(c), "missing witness accepted");
        }
        c.proof.digests = original;
        if (c.proof.leaves > 1) {
            uint256 location = c.proof.location;
            c.proof.location = (location + 1) % c.proof.leaves;
            assertFalse(exclusion ? this.checkedExclusion(c, key) : this.checked(c), "wrong location accepted");
            c.proof.location = location;
        }
        ++c.proof.leaves;
        assertFalse(exclusion ? this.checkedExclusion(c, key) : this.checked(c));
        --c.proof.leaves;
        c.proof.location = c.proof.leaves;
        assertFalse(exclusion ? this.checkedExclusion(c, key) : this.checked(c));
        c.proof.location = type(uint256).max;
        assertFalse(exclusion ? this.checkedExclusion(c, key) : this.checked(c));
        c.proof.location = 0;
        c.proof.leaves = 0;
        assertFalse(exclusion ? this.checkedExclusion(c, key) : this.checked(c));
        c.proof.leaves = (uint256(1) << 62) + (_mmb() ? 31 : 1);
        assertFalse(exclusion ? this.checkedExclusion(c, key) : this.checked(c));
        c.proof.leaves = type(uint256).max;
        assertFalse(exclusion ? this.checkedExclusion(c, key) : this.checked(c));
    }

    /// @dev Exercise absent, pending, partial, and combined witness shapes on rejection paths.
    function test_TamperedProofsAndBounds() public view {
        uint256[7] memory sizes = [uint256(1), 256, 257, 383, 512, 513, 639];
        for (uint256 i; i < sizes.length; ++i) {
            rejectMutations(this.build(sizes[i], sizes[i] - 1, hex"010203", true));
            QMDBCase memory c = this.build(sizes[i], 0, hex"010203", true);
            c.proof.inactivePeaks = type(uint256).max;
            assertFalse(this.checked(c));
        }
    }

    /// @dev Absent fields must be zero even if the supplied root ignores them.
    function test_AbsentDigestsAndZeroRoot() public view {
        QMDBCase memory c = this.build(512, 0, "", true);
        assertEq(c.proof.partialDigest, 0);
        c.proof.partialDigest = bytes32(uint256(1));
        assertFalse(this.checked(c));
        c = this.build(383, 0, "", true);
        assertEq(c.proof.pending, 0);
        c.proof.pending = bytes32(uint256(1));
        assertFalse(this.checked(c));
        c = this.build(1, 0, "", true);
        c.root = 0;
        assertFalse(this.checked(c));
        c.proof.chunk = new bytes(0);
        assertFalse(this.checked(c));
    }

    /// @dev Distinct eager and delayed merge histories bind operations to their append family.
    function test_CrossFamilyRejection() public view {
        uint256[3] memory sizes = [uint256(8), 256, 512];
        for (uint256 i; i < sizes.length; ++i) {
            QMDBCase memory c = this.build(sizes[i], sizes[i] - 1, hex"010203", true);
            assertTrue(this.checked(c));
            this.rejectOtherFamily(c);
        }
    }

    /// @dev Values have a fixed size per database. Their bytes do not affect interval ordering.
    function test_ExclusionIntervalsAndValueLengths() public view {
        uint256[8] memory lengths = [uint256(0), 1, 31, 32, 33, 64, 97, 257];
        bytes32[7] memory keys = [
            bytes32(0),
            bytes32(uint256(9)),
            bytes32(uint256(10)),
            bytes32(uint256(15)),
            bytes32(uint256(20)),
            bytes32(uint256(21)),
            bytes32(type(uint256).max)
        ];
        for (uint256 i; i < lengths.length; ++i) {
            bytes memory value = new bytes(lengths[i]);
            for (uint256 j; j < value.length; ++j) {
                value[j] = bytes1(uint8(j + 1));
            }
            for (uint256 mode; mode < 3; ++mode) {
                bytes32 left = bytes32(uint256(mode == 1 ? 20 : 10));
                bytes32 right = bytes32(uint256(mode == 0 ? 20 : 10));
                QMDBCase memory c = this.build(383, 127, abi.encodePacked(bytes1(0xd2), left, value, right), true);
                for (uint256 j; j < keys.length; ++j) {
                    bool expected = mode == 0
                        ? keys[j] > left && keys[j] < right
                        : mode == 1 ? keys[j] > left || keys[j] < right : keys[j] != left;
                    assertEq(this.checkedExclusion(c, keys[j]), expected, "cyclic interval membership");
                }
            }
        }
    }

    /// @dev Arbitrary keys exercise cyclic ordering against an authenticated update.
    function testFuzz_ExclusionIntervals(bytes32 left, bytes32 right, bytes32 key, bytes memory value) public view {
        QMDBCase memory c = this.build(2, 1, abi.encodePacked(bytes1(0xd2), left, value, right), true);
        bool expected =
            left < right ? left < key && key < right : left > right ? key > left || key < right : key != left;
        assertEq(this.checkedExclusion(c, key), expected);
    }

    /// @dev Empty commits authenticate their own location as the floor, with optional fixed-size metadata.
    function test_ExclusionEmptyCommit() public view {
        uint256[6] memory lengths = [uint256(0), 1, 31, 32, 33, 97];
        for (uint256 i; i < lengths.length; ++i) {
            bytes memory metadata = new bytes(lengths[i]);
            for (uint256 j; j < metadata.length; ++j) {
                metadata[j] = bytes1(uint8(j + 1));
            }
            bytes memory operation = abi.encodePacked(hex"d301", metadata, uint64(256), new bytes(55));
            QMDBCase memory c = this.build(257, 256, operation, true);
            assertTrue(this.checkedExclusion(c, 0));
            assertTrue(this.checkedExclusion(c, bytes32(type(uint256).max)));
            operation = abi.encodePacked(hex"d300", new bytes(lengths[i]), uint64(256), new bytes(55));
            assertTrue(this.checkedExclusion(this.build(257, 256, operation, true), 0));
            operation = abi.encodePacked(hex"d301", metadata, uint64(255), new bytes(55));
            c = this.build(257, 256, operation, true);
            assertTrue(this.checked(c), "wrong-floor operation membership");
            assertFalse(this.checkedExclusion(c, 0), "wrong floor");
        }
        bytes memory absent = abi.encodePacked(hex"d300", uint64(0), new bytes(55));
        assertTrue(this.checkedExclusion(this.build(1, 0, absent, true), bytes32(uint256(7))));
        absent = abi.encodePacked(hex"d300", uint64(382), new bytes(55));
        assertTrue(this.checkedExclusion(this.build(383, 382, absent, true), 0));
        absent = abi.encodePacked(hex"d300", uint64(381), new bytes(55));
        assertFalse(this.checkedExclusion(this.build(383, 382, absent, true), 0));
    }

    /// @dev Malformed operation bytes remain invalid even when the active proof authenticates them.
    function test_ExclusionMalformedOperations() public view {
        assertFalse(this.checkedExclusion(this.build(1, 0, "", true), 0));
        for (uint256 length = 1; length < 65; ++length) {
            bytes memory operation = new bytes(length);
            operation[0] = 0xd2;
            assertFalse(this.checkedExclusion(this.build(1, 0, operation, true), bytes32(uint256(1))));
            operation[0] = 0xd3;
            assertFalse(this.checkedExclusion(this.build(1, 0, operation, true), bytes32(uint256(1))));
        }
        bytes memory commit = abi.encodePacked(hex"d300", uint64(0), new bytes(55));
        for (uint256 tag; tag < 256; ++tag) {
            if (tag == 0xd2 || tag == 0xd3) continue;
            commit[0] = bytes1(uint8(tag));
            assertFalse(this.checkedExclusion(this.build(1, 0, commit, true), bytes32(uint256(1))));
        }
        commit[0] = 0xd3;
        for (uint256 flag = 2; flag < 256; ++flag) {
            commit[1] = bytes1(uint8(flag));
            assertFalse(this.checkedExclusion(this.build(1, 0, commit, true), 0));
        }
        commit[1] = 0;
        for (uint256 i = 10; i < commit.length; ++i) {
            commit[i] = 0x01;
            assertFalse(this.checkedExclusion(this.build(1, 0, commit, true), 0), "nonzero commit padding");
            commit[i] = 0;
        }
        commit = abi.encodePacked(hex"d300", new bytes(33), uint64(0), new bytes(55));
        for (uint256 i = 2; i < 35; ++i) {
            commit[i] = 0x01;
            assertFalse(this.checkedExclusion(this.build(1, 0, commit, true), 0), "nonzero absent metadata");
            commit[i] = 0;
        }
        commit = abi.encodePacked(hex"d301", bytes32(uint256(42)), uint64(0), new bytes(55));
        commit[commit.length - 1] = 0x01;
        assertFalse(this.checkedExclusion(this.build(1, 0, commit, true), 0), "metadata commit padding");
    }

    /// @dev Interval and empty witnesses share the complete active-operation authentication contract.
    function test_ExclusionProofAuthentication() public view {
        uint256[7] memory sizes = [uint256(1), 256, 257, 383, 512, 513, 639];
        bytes memory update = abi.encodePacked(bytes1(0xd2), bytes32(uint256(10)), hex"112233", bytes32(uint256(20)));
        for (uint256 i; i < sizes.length; ++i) {
            uint256 location = sizes[i] - 1;
            for (uint256 mode; mode < 2; ++mode) {
                bytes memory operation =
                    mode == 0 ? update : abi.encodePacked(hex"d300", uint64(location), new bytes(55));
                QMDBCase memory c = this.build(sizes[i], location, operation, true);
                rejectMutations(c, true, bytes32(uint256(15)));
                c = this.build(sizes[i], location, operation, false);
                assertFalse(this.checkedExclusion(c, bytes32(uint256(15))), "inactive exclusion operation");
                c = this.build(sizes[i], location, operation, true);
                c.operation[c.operation.length / 2] ^= 0x01;
                assertFalse(this.checkedExclusion(c, bytes32(uint256(15))), "operation tampering");
            }
        }
    }

    /// @dev Decode the Rust oracle's flat ABI tuple without imposing an operation type.
    function generate(uint256 leaves, uint256 location, uint256 floor) internal returns (QMDBCase memory c) {
        return generate(leaves, location, floor, 32);
    }

    /// @dev Decode a Rust proof generated with a caller-selected chunk size.
    function generate(uint256 leaves, uint256 location, uint256 floor, uint256 chunkBytes)
        internal
        returns (QMDBCase memory c)
    {
        string[] memory args = new string[](15);
        args[0] = string.concat(vm.projectRoot(), "/../target/release/commonware-sol-fuzz");
        args[1] = "qmdb";
        args[2] = "current";
        args[3] = "--leaves";
        args[4] = vm.toString(leaves);
        args[5] = "--location";
        args[6] = vm.toString(location);
        args[7] = "--seed";
        args[8] = "71";
        args[9] = "--inactivity-floor";
        args[10] = vm.toString(floor);
        args[11] = "--family";
        args[12] = _mmb() ? "mmb" : "mmr";
        args[13] = "--chunk-bytes";
        args[14] = vm.toString(chunkBytes);
        (
            c.root,
            c.proof.leaves,
            c.proof.location,
            c.proof.inactivePeaks,
            c.proof.chunk,
            c.proof.opsRoot,
            c.proof.pending,
            c.proof.partialDigest,
            c.proof.digests,
            c.operation
        ) =
            abi.decode(
                _ffi(args), (bytes32, uint256, uint256, uint256, bytes, bytes32, bytes32, bytes32, bytes32[], bytes)
            );
        c.chunkBytes = chunkBytes;
        assertEq(c.proof.leaves, leaves);
        assertEq(c.proof.location, location);
    }

    /// @dev Decode the production Current proof and activity verdict for an unordered log.
    function generateUnordered(
        uint256 leaves,
        uint256 location,
        uint256 floor,
        string memory encoding,
        string memory operation,
        string memory history,
        uint256 valueLength
    ) internal returns (QMDBCase memory c, bool expected) {
        (
            c.root,
            c.proof.leaves,
            c.proof.location,
            c.proof.inactivePeaks,
            c.proof.chunk,
            c.proof.opsRoot,
            c.proof.pending,
            c.proof.partialDigest,
            c.proof.digests,
            c.operation,
            expected
        ) =
            abi.decode(
                unorderedFixture(leaves, location, floor, encoding, operation, history, true, valueLength, 32),
                (bytes32, uint256, uint256, uint256, bytes, bytes32, bytes32, bytes32, bytes32[], bytes, bool)
            );
        c.chunkBytes = 32;
    }

    /// @dev Active unordered updates bind their bytes and nonzero inactive peak boundary.
    function test_DifferentialUnorderedOperations() public {
        string[4] memory operations = [string("update"), "delete", "commit", "commit-metadata"];
        uint256[8] memory lengths = [uint256(0), 1, 31, 32, 33, 127, 128, 129];
        for (uint256 encoding; encoding < 2; ++encoding) {
            for (uint256 i; i < operations.length; ++i) {
                for (uint256 j; j < (encoding == 0 ? 1 : lengths.length); ++j) {
                    (QMDBCase memory c, bool expected) = generateUnordered(
                        1023,
                        1022,
                        i == 0 ? 768 : 0,
                        encoding == 0 ? "fixed" : "variable",
                        operations[i],
                        "",
                        lengths[j]
                    );
                    if (i == 0) assertGt(c.proof.inactivePeaks, 0, "unordered inactive prefix missing");
                    assertEq(expected, i != 1, "delete activity");
                    assertEq(this.checked(c), expected, "Rust unordered activity disagreement");
                    if (expected) rejectMutations(c);
                }
            }
        }
    }

    /// @dev Replay marks overwritten updates and deletes inactive, and only the final update active.
    function test_DifferentialUnorderedHistory() public {
        uint256[5] memory sizes = [uint256(255), 256, 257, 383, 639];
        for (uint256 encoding; encoding < 2; ++encoding) {
            for (uint256 history; history < 2; ++history) {
                for (uint256 i; i < sizes.length; ++i) {
                    for (uint256 target; target < 2; ++target) {
                        uint256 location = target == 0 ? 0 : sizes[i] - 1;
                        (QMDBCase memory c, bool expected) = generateUnordered(
                            sizes[i],
                            location,
                            0,
                            encoding == 0 ? "fixed" : "variable",
                            "update",
                            history == 0 ? "updated" : "deleted",
                            128
                        );
                        assertEq(expected, history == 0 && target == 1, "history activity");
                        assertEq(this.checked(c), expected, "Rust history disagreement");
                        if (!expected) {
                            uint256 bit = location % 256;
                            c.proof.chunk[bit >> 3] |= bytes1(uint8(1 << (bit & 7)));
                            assertFalse(this.checked(c), "forged activity accepted");
                        }
                    }
                }
            }
        }
    }

    /// @dev Production Commonware proofs cross every pending and partial chunk transition.
    function test_DifferentialBoundaryTrees() public {
        uint256[15] memory sizes = [uint256(1), 2, 255, 256, 257, 382, 383, 511, 512, 513, 638, 639, 767, 1023, 2047];
        for (uint256 i; i < sizes.length; ++i) {
            assertTrue(this.checked(generate(sizes[i], 0, 0)));
            assertTrue(this.checked(generate(sizes[i], sizes[i] - 1, 0)));
            if (sizes[i] > 256) assertTrue(this.checked(generate(sizes[i], 256, 0)));
        }
    }

    /// @dev Production proofs cover every supported chunk size on both sides of chunk boundaries.
    function test_DifferentialVariableChunks() public {
        uint256[6] memory sizes = [uint256(1), 2, 16, 32, 64, 128];
        for (uint256 i; i < sizes.length; ++i) {
            uint256 chunkBytes = sizes[i];
            uint256 chunkBits = chunkBytes * 8;
            uint256 leaves = 2 * chunkBits + 1;
            assertTrue(this.checked(generate(leaves, 0, 0, chunkBytes)));
            assertTrue(this.checked(generate(leaves, chunkBits, 0, chunkBytes)));
            assertTrue(this.checked(generate(leaves, leaves - 1, 0, chunkBytes)));
        }
    }

    /// @dev Random active locations and inactivity floors exercise production proof geometry.
    function testFuzz_DifferentialTrees(uint16 leavesSeed, uint16 locationSeed, uint16 floorSeed) public {
        uint256 n = uint256(leavesSeed) % 1536 + 1;
        uint256 floor = uint256(floorSeed) % n;
        uint256 location = floor + uint256(locationSeed) % (n - floor);
        QMDBCase memory c = generate(n, location, floor);
        assertTrue(this.checked(c));
        c.operation = abi.encodePacked(c.operation, bytes1(0));
        assertFalse(this.checked(c), "modified oracle operation accepted");
    }

    /// @dev Chunk-aligned inactive prefixes bind the root and alter witness ordering.
    function test_DifferentialInactivePeaks() public {
        uint256[4] memory floors = [uint256(512), 768, 1024, 1280];
        for (uint256 i; i < floors.length; ++i) {
            uint256 n = i < 2 ? 1023 : 1535;
            QMDBCase memory c = generate(n, floors[i], floors[i]);
            assertTrue(this.checked(c));
            c = generate(n, n - 1, floors[i]);
            uint256 inactive = c.proof.inactivePeaks;
            assertGt(inactive, 0, "fixture has no inactive peaks");
            rejectMutations(c);
            c = generate(n, n - 1, floors[i]);
            c.proof.inactivePeaks = 0;
            assertFalse(this.checked(c));
        }
    }

    /// @dev Decode an exclusion fixture and the Rust verifier's verdict for the queried key.
    function generateExclusion(uint256 leaves, uint256 location, bytes32 key, string memory mode, bool metadata)
        internal
        returns (QMDBCase memory c, bool expected)
    {
        string[] memory args = new string[](metadata ? 20 : 19);
        args[0] = string.concat(vm.projectRoot(), "/../target/release/commonware-sol-fuzz");
        args[1] = "qmdb";
        args[2] = "exclude";
        args[3] = "--leaves";
        args[4] = vm.toString(leaves);
        args[5] = "--location";
        args[6] = vm.toString(location);
        args[7] = "--seed";
        args[8] = "71";
        args[9] = "--keyhex";
        args[10] = vm.toString(key);
        args[11] = "--family";
        args[12] = _mmb() ? "mmb" : "mmr";
        args[13] = "--mode";
        args[14] = mode;
        args[15] = "--inactivity-floor";
        args[16] = "0";
        args[17] = "--chunk-bytes";
        args[18] = "32";
        if (metadata) args[19] = "--metadata";
        (
            c.root,
            c.proof.leaves,
            c.proof.location,
            c.proof.inactivePeaks,
            c.proof.chunk,
            c.proof.opsRoot,
            c.proof.pending,
            c.proof.partialDigest,
            c.proof.digests,
            c.operation,
            expected
        ) =
            abi.decode(
                _ffi(args),
                (bytes32, uint256, uint256, uint256, bytes, bytes32, bytes32, bytes32, bytes32[], bytes, bool)
            );
        c.chunkBytes = 32;
        assertEq(c.proof.leaves, leaves);
        assertEq(c.proof.location, location);
    }

    /// @dev The oracle's verdict comes from Rust ExclusionProof::verify on the same query and root.
    function test_DifferentialExclusion() public {
        uint256[8] memory sizes = [uint256(1), 255, 256, 257, 383, 512, 639, 1023];
        for (uint256 i; i < sizes.length; ++i) {
            uint256 n = sizes[i];
            uint256[2] memory locations = [uint256(0), n - 1];
            for (uint256 j; j < locations.length; ++j) {
                uint256 location = locations[j];
                bytes32 left = bytes32(2 * (location + 1));
                bytes32 right = bytes32(2 * ((location + 1) % n + 1));
                bytes32[4] memory queries = [bytes32(uint256(left) + 1), left, right, bytes32(0)];
                for (uint256 k; k < queries.length; ++k) {
                    (QMDBCase memory c, bool expected) = generateExclusion(n, location, queries[k], "interval", false);
                    bool member = n == 1
                        ? queries[k] != left
                        : location == n - 1
                            ? queries[k] > left || queries[k] < right
                            : queries[k] > left && queries[k] < right;
                    assertEq(expected, member, "oracle interval fixture");
                    assertEq(this.checkedExclusion(c, queries[k]), expected, "Rust interval disagreement");
                }
            }
            bytes32 present = bytes32(2 * n);
            for (uint256 j; j < 2; ++j) {
                bytes32 query = j == 0 ? present : bytes32(0);
                (QMDBCase memory c, bool expected) = generateExclusion(n, n - 1, query, "single", false);
                assertEq(expected, j != 0, "oracle single fixture");
                assertEq(this.checkedExclusion(c, query), expected, "Rust single disagreement");
                (c, expected) = generateExclusion(n, n - 1, query, "empty", j != 0);
                assertTrue(expected, "oracle empty fixture");
                assertTrue(this.checkedExclusion(c, query), "Rust empty disagreement");
            }
        }
    }

    /// @dev Measure only the verifier call for grafted, pending, and partial target chunks.
    function test_Gas() public {
        uint256[3] memory locations = [uint256(17), 256, 637];
        string[3] memory names = [string("grafted"), _mmb() ? "pending" : "grafted-second", "partial"];
        for (uint256 i; i < locations.length; ++i) {
            QMDBCase memory c = this.build(638, locations[i], new bytes(97), true);
            assertTrue(this.verify32(c));
            emit log_named_uint(
                string.concat(_group(_mmb() ? "QMDB" : "QMDBMMR"), "/", names[i]), vm.lastFrameGas().gasTotalUsed
            );
        }
    }

    /// @dev Exercise variable exclusion with the membership verifier's memory checks.
    function checkedVariableExclusion(
        QMDBCase calldata c,
        bytes calldata key,
        Current.ExclusionEncoding calldata encoding
    ) external view returns (bool) {
        return _checked(c, 2, key, encoding);
    }

    /// @dev Encode a canonical unsigned varint independently of the verifier's decoder.
    function _unsigned(uint256 value) internal pure returns (bytes memory encoded) {
        do {
            uint8 octet = uint8(value & 127);
            value >>= 7;
            encoded = bytes.concat(encoded, bytes1(octet | (value == 0 ? 0 : 128)));
        } while (value != 0);
    }

    /// @dev Frame a byte vector with Commonware's unsigned length prefix.
    function _vector(bytes memory value) internal pure returns (bytes memory) {
        return bytes.concat(_unsigned(value.length), value);
    }

    /// @dev Compare raw keys one byte at a time as an independent ordering oracle.
    function _keyOrder(bytes memory a, bytes memory b) internal pure returns (int256) {
        for (uint256 i; i < a.length && i < b.length; ++i) {
            if (a[i] != b[i]) return a[i] < b[i] ? int256(-1) : int256(1);
        }
        return a.length == b.length ? int256(0) : a.length < b.length ? int256(-1) : int256(1);
    }

    /// @dev Authenticate arbitrary operation bytes before testing their exclusion interpretation.
    function _variableCase(bytes memory operation, bytes memory key, bool expected) internal view {
        QMDBCase memory c = this.build(1, 0, operation, true);
        Current.ExclusionEncoding memory encoding = Current.ExclusionEncoding(type(uint256).max, type(uint256).max);
        assertEq(this.checkedVariableExclusion(c, key, encoding), expected);
    }

    /// @dev Prefix keys, empty keys, and full-word boundaries retain Rust's raw byte ordering.
    function testFuzz_VariableExclusionOrdering(bytes memory left, bytes memory right, bytes memory query) public view {
        if (left.length > 160 || right.length > 160 || query.length > 160) return;
        bytes memory operation = bytes.concat(hex"d2", _vector(left), hex"00", _vector(right));
        int256 afterLeft = _keyOrder(query, left);
        int256 beforeRight = _keyOrder(query, right);
        bool expected = _keyOrder(left, right) < 0 ? afterLeft > 0 && beforeRight < 0 : afterLeft > 0 || beforeRight < 0;
        _variableCase(operation, query, expected);
    }

    /// @dev Explicit prefixes and zero suffixes exercise comparisons that padded words cannot distinguish.
    function test_VariableExclusionPrefixes() public view {
        _variableCase(hex"d201000003000001", hex"0000", true);
        _variableCase(hex"d201000003000001", hex"00", false);
        _variableCase(hex"d201000003000001", hex"000001", false);
        _variableCase(hex"d2010100020001", hex"", true);
        _variableCase(hex"d2010100020001", hex"0002", false);
        _variableCase(hex"d20101000101", hex"0100", true);
        _variableCase(hex"d20101000101", hex"01", false);
        _variableCase(hex"d200000100", hex"", false);
        _variableCase(hex"d2000000", hex"00", true);
        uint256[10] memory lengths = [uint256(1), 31, 32, 33, 63, 64, 65, 128, 256, 1024];
        for (uint256 i; i < lengths.length; ++i) {
            bytes memory left = new bytes(lengths[i]);
            bytes memory right = bytes.concat(left, hex"0001");
            bytes memory operation = bytes.concat(hex"d2", _vector(left), hex"00", _vector(right));
            _variableCase(operation, bytes.concat(left, hex"00"), true);
            _variableCase(operation, left, false);
            _variableCase(operation, right, false);
        }
    }

    /// @dev Fixed fields and byte vectors compose independently within variable operation encoding.
    function test_VariableExclusionMixedFields() public view {
        uint256 variableSize = type(uint256).max;
        for (uint256 keySize; keySize < 2; ++keySize) {
            for (uint256 valueSize; valueSize < 2; ++valueSize) {
                Current.ExclusionEncoding memory encoding =
                    Current.ExclusionEncoding(keySize == 0 ? variableSize : 1, valueSize == 0 ? variableSize : 1);
                bytes memory left = keySize == 0 ? bytes(hex"0101") : bytes(hex"01");
                bytes memory right = keySize == 0 ? bytes(hex"0103") : bytes(hex"03");
                bytes memory value = valueSize == 0 ? bytes(hex"01ff") : bytes(hex"ff");
                QMDBCase memory c = this.build(1, 0, bytes.concat(hex"d2", left, value, right), true);
                assertTrue(this.checkedVariableExclusion(c, hex"02", encoding));
                assertFalse(this.checkedVariableExclusion(c, hex"01", encoding));
                assertFalse(this.checkedVariableExclusion(c, hex"03", encoding));
                if (keySize != 0) assertFalse(this.checkedVariableExclusion(c, hex"0002", encoding));
                c = this.build(1, 0, bytes.concat(hex"d301", value, hex"00"), true);
                assertTrue(this.checkedVariableExclusion(c, hex"02", encoding));
                c = this.build(1, 0, hex"d30000", true);
                assertTrue(this.checkedVariableExclusion(c, hex"02", encoding));
            }
        }
        Current.ExclusionEncoding memory emptyValue = Current.ExclusionEncoding(variableSize, 0);
        QMDBCase memory zero = this.build(1, 0, hex"d201010103", true);
        assertTrue(this.checkedVariableExclusion(zero, hex"02", emptyValue));
        zero = this.build(1, 0, hex"d30100", true);
        assertTrue(this.checkedVariableExclusion(zero, hex"", emptyValue));
        emptyValue.keySize = variableSize - 1;
        assertFalse(this.checkedVariableExclusion(zero, hex"", emptyValue));
        emptyValue.keySize = variableSize;
        emptyValue.valueSize = variableSize - 1;
        assertFalse(this.checkedVariableExclusion(zero, hex"", emptyValue));
    }

    /// @dev Length-prefix transitions and optional empty metadata preserve exact operation framing.
    function test_VariableExclusionLengthsAndCommits() public view {
        uint256[7] memory sizes = [uint256(0), 1, 32, 127, 128, 16383, 16384];
        for (uint256 i; i < sizes.length; ++i) {
            bytes memory value = new bytes(sizes[i]);
            _variableCase(bytes.concat(hex"d20101", _vector(value), hex"0103"), hex"02", true);
            _variableCase(bytes.concat(hex"d301", _vector(value), hex"00"), hex"02", true);
        }
        _variableCase(hex"d30000", hex"", true);
        _variableCase(hex"d3010000", hex"", true);
        _variableCase(hex"d30001", hex"", false);
        Current.ExclusionEncoding memory encoding = Current.ExclusionEncoding(type(uint256).max, type(uint256).max);
        for (uint256 location = 127; location <= 128; ++location) {
            QMDBCase memory c = this.build(location + 1, location, bytes.concat(hex"d300", _unsigned(location)), true);
            assertTrue(this.checkedVariableExclusion(c, hex"", encoding));
            c = this.build(location + 1, location, bytes.concat(hex"d300", _unsigned(location - 1)), true);
            assertFalse(this.checkedVariableExclusion(c, hex"", encoding));
        }
    }

    /// @dev Authenticated malformed operations cannot shift key boundaries or alias commit floors.
    function test_VariableExclusionMalformed() public view {
        bytes[19] memory invalid = [
            bytes(hex""),
            hex"d1",
            hex"d2",
            hex"d3",
            hex"d30200",
            hex"d300",
            hex"d3008000",
            hex"d30080808080808080808002",
            hex"d3008080808080808080808000",
            hex"d3000000",
            hex"d301800000",
            hex"d301020000",
            hex"d2810001000103",
            hex"d2808080801001000103",
            hex"d2010180000103",
            hex"d2010100810003",
            hex"d2010100010300",
            hex"d20101000203",
            hex"d201010001"
        ];
        for (uint256 i; i < invalid.length; ++i) {
            _variableCase(invalid[i], hex"02", false);
        }
        bytes memory valid = hex"d20101000103";
        for (uint256 length; length < valid.length; ++length) {
            bytes memory truncated = new bytes(length);
            for (uint256 i; i < length; ++i) {
                truncated[i] = valid[i];
            }
            _variableCase(truncated, hex"02", false);
        }
    }

    /// @dev Exclusion remains bound to activity, operation bytes, witnesses, and the trusted root.
    function test_VariableExclusionProofBinding() public view {
        Current.ExclusionEncoding memory encoding = Current.ExclusionEncoding(type(uint256).max, type(uint256).max);
        bytes memory operation = hex"d20101000103";
        QMDBCase memory c = this.build(638, 17, operation, true);
        assertTrue(this.checkedVariableExclusion(c, hex"02", encoding));
        c.root ^= bytes32(uint256(1));
        assertFalse(this.checkedVariableExclusion(c, hex"02", encoding));
        c.root ^= bytes32(uint256(1));
        c.operation[2] = 0x00;
        assertFalse(this.checkedVariableExclusion(c, hex"02", encoding));
        c.operation[2] = 0x01;
        c.proof.digests[0] ^= bytes32(uint256(1));
        assertFalse(this.checkedVariableExclusion(c, hex"02", encoding));
        c = this.build(638, 17, operation, false);
        assertFalse(this.checkedVariableExclusion(c, hex"02", encoding));
    }

    /// @dev Rust serializes the operation and evaluates exclusion under the same trusted field schema.
    function checkVariableExclusion(
        uint256 leaves,
        uint256 location,
        bytes memory key,
        Current.ExclusionEncoding memory encoding,
        uint256 chunkBytes,
        string[] memory options
    ) internal returns (bool expected) {
        QMDBCase memory c;
        uint256 variableSize = type(uint256).max;
        string[] memory args = new string[](
            17 + (encoding.keySize != variableSize ? 2 : 0) + (encoding.valueSize != variableSize ? 2 : 0)
                + options.length
        );
        args[0] = string.concat(vm.projectRoot(), "/../target/release/commonware-sol-fuzz");
        args[1] = "qmdb";
        args[2] = "exclude-variable";
        args[3] = "--leaves";
        args[4] = vm.toString(leaves);
        args[5] = "--location";
        args[6] = vm.toString(location);
        args[7] = "--seed";
        args[8] = "71";
        args[9] = "--keyhex";
        args[10] = vm.toString(key);
        args[11] = "--family";
        args[12] = _mmb() ? "mmb" : "mmr";
        args[13] = "--chunk-bytes";
        args[14] = vm.toString(chunkBytes);
        args[15] = "--inactivity-floor";
        args[16] = "0";
        uint256 cursor = 17;
        if (encoding.keySize != variableSize) {
            args[cursor++] = "--key-size";
            args[cursor++] = vm.toString(encoding.keySize);
        }
        if (encoding.valueSize != variableSize) {
            args[cursor++] = "--value-size";
            args[cursor++] = vm.toString(encoding.valueSize);
        }
        for (uint256 i; i < options.length; ++i) {
            args[cursor++] = options[i];
        }
        (
            c.root,
            c.proof.leaves,
            c.proof.location,
            c.proof.inactivePeaks,
            c.proof.chunk,
            c.proof.opsRoot,
            c.proof.pending,
            c.proof.partialDigest,
            c.proof.digests,
            c.operation,
            expected
        ) =
            abi.decode(
                _ffi(args),
                (bytes32, uint256, uint256, uint256, bytes, bytes32, bytes32, bytes32, bytes32[], bytes, bool)
            );
        c.chunkBytes = chunkBytes;
        assertEq(c.proof.leaves, leaves);
        assertEq(c.proof.location, location);
        assertTrue(this.checked(c), "Rust exclusion operation is not active");
        assertEq(this.checkedVariableExclusion(c, key, encoding), expected, "Rust variable exclusion disagreement");
    }

    /// @dev Rust's raw-byte ordering covers prefix intervals, wraparound, mixed codecs, and empty commits.
    function test_DifferentialVariableExclusion() public {
        uint256 variableSize = type(uint256).max;
        Current.ExclusionEncoding memory encoding = Current.ExclusionEncoding(variableSize, variableSize);
        string[] memory options = new string[](4);
        options[0] = "--keys";
        options[1] = "00,01,010000";
        options[2] = "--mode";
        options[3] = "interval";
        bytes[5] memory queries = [bytes(hex"0000"), hex"00", hex"01", hex"0100", hex""];
        uint256[5] memory locations = [uint256(0), 0, 0, 1, 2];
        bool[5] memory expected = [true, false, false, true, true];
        for (uint256 i; i < queries.length; ++i) {
            bool actual = checkVariableExclusion(3, locations[i], queries[i], encoding, 1, options);
            assertEq(actual, expected[i], "Rust prefix fixture");
        }
        options[1] = "00,02,04";
        encoding.keySize = 1;
        assertTrue(checkVariableExclusion(3, 0, hex"01", encoding, 64, options));
        encoding.valueSize = 4;
        assertTrue(checkVariableExclusion(3, 0, hex"01", encoding, 16, options));
        encoding.keySize = variableSize;
        encoding.valueSize = 0;
        assertTrue(checkVariableExclusion(3, 0, hex"01", encoding, 2, options));

        encoding.valueSize = variableSize;
        options = new string[](5);
        options[0] = "--mode";
        options[1] = "empty";
        options[2] = "--metadata";
        options[3] = "--value-length";
        options[4] = "0";
        assertTrue(checkVariableExclusion(129, 128, hex"", encoding, 16, options));
        options[4] = "128";
        assertTrue(checkVariableExclusion(129, 128, hex"00", encoding, 1, options));

        options = new string[](2);
        options[0] = "--mode";
        options[1] = "empty";
        assertTrue(checkVariableExclusion(129, 128, hex"", encoding, 128, options));
        options[1] = "single";
        assertTrue(checkVariableExclusion(129, 128, hex"", encoding, 2, options));

        options = new string[](4);
        options[0] = "--mode";
        options[1] = "single";
        options[2] = "--keys";
        options[3] = "0x";
        encoding.keySize = 0;
        encoding.valueSize = 0;
        bool absent = checkVariableExclusion(1, 0, hex"", encoding, 32, options);
        assertFalse(absent, "zero-width singleton key exists");
    }

    /// @dev Random locations compare endpoint and proper-prefix queries against Rust across chunk sizes.
    function testFuzz_DifferentialVariableExclusion(
        uint16 leavesSeed,
        uint16 locationSeed,
        uint8 querySeed,
        uint8 chunkSeed
    ) public {
        uint256 leaves = uint256(leavesSeed) % 128 + 1;
        uint256 location = uint256(locationSeed) % leaves;
        uint256 index = querySeed % 4 == 1 ? (location + 1) % leaves : location;
        bytes memory query = abi.encodePacked(uint64(index), new bytes(index % 3));
        if (querySeed % 4 == 2) query = bytes.concat(query, hex"00");
        if (querySeed % 4 == 3) query = hex"";
        uint256[6] memory chunks = [uint256(1), 2, 16, 32, 64, 128];
        Current.ExclusionEncoding memory encoding = Current.ExclusionEncoding(type(uint256).max, type(uint256).max);
        string[] memory options = new string[](2);
        options[0] = "--mode";
        options[1] = "interval";
        checkVariableExclusion(leaves, location, query, encoding, chunks[chunkSeed % chunks.length], options);
    }
}

contract LibQMDBCurrentSha256Test is LibQMDBCurrentTest {
    /// @dev Run the same compatibility and rejection cases through the SHA-256 precompile.
    function _hasher() internal pure override returns (address) {
        return address(2);
    }
}

contract LibQMDBCurrentMMRTest is LibQMDBCurrentTest {
    /// @dev Select the eagerly merged MMR append family.
    function _mmb() internal pure override returns (bool) {
        return false;
    }
}

contract LibQMDBCurrentMMRSha256Test is LibQMDBCurrentMMRTest {
    /// @dev Run MMR compatibility and rejection cases through the SHA-256 precompile.
    function _hasher() internal pure override returns (address) {
        return address(2);
    }
}
