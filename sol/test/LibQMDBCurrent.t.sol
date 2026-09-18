// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.15;

import { HashTest } from "./Common.t.sol";
import { LibQMDBCurrent } from "../src/qmdb/LibQMDBCurrent.sol";

/// @dev Operations remain opaque byte strings.
struct QMDBCase {
    bytes32 root;
    bytes operation;
    LibQMDBCurrent.Proof proof;
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

contract LibQMDBCurrentTest is HashTest {
    /// @dev Select the delayed-merge MMB append family.
    function _mmb() internal pure virtual returns (bool) {
        return true;
    }

    /// @dev Expose the calldata proof entrypoint for tests and gas measurements.
    function verify(QMDBCase calldata c) external view returns (bool) {
        return _mmb()
            ? LibQMDBCurrent.verify(c.root, c.operation, c.proof, _hasher())
            : LibQMDBCurrent.verifyMMR(c.root, c.operation, c.proof, _hasher());
    }

    /// @dev Reject the supplied root and proof under the other append family's topology.
    function rejectOtherFamily(QMDBCase calldata c) external view {
        bool valid = _mmb()
            ? LibQMDBCurrent.verifyMMR(c.root, c.operation, c.proof, _hasher())
            : LibQMDBCurrent.verify(c.root, c.operation, c.proof, _hasher());
        assertFalse(valid, "proof accepted by the other append family");
    }

    /// @dev Check caller allocations, dirty scratch, and subsequent allocations on every exit path.
    function checked(QMDBCase calldata c) external view returns (bool) {
        return _checked(c, false, 0);
    }

    /// @dev Exercise exclusion with the same caller-memory checks as membership.
    function checkedExclusion(QMDBCase calldata c, bytes32 key) external view returns (bool) {
        return _checked(c, true, key);
    }

    /// @dev Repeated verification preserves inputs and leaves subsequent allocations zeroed.
    function _checked(QMDBCase calldata c, bool exclusion, bytes32 key) internal view returns (bool valid) {
        bytes memory operation = c.operation;
        bytes memory guard = abi.encode(c);
        bytes32 beforeInputs = keccak256(abi.encode(operation, guard));
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
            if (exclusion) {
                result = _mmb()
                    ? LibQMDBCurrent.verifyExclusion(c.root, key, operation, c.proof, _hasher())
                    : LibQMDBCurrent.verifyExclusionMMR(c.root, key, operation, c.proof, _hasher());
            } else {
                result = _mmb()
                    ? LibQMDBCurrent.verify(c.root, operation, c.proof, _hasher())
                    : LibQMDBCurrent.verifyMMR(c.root, operation, c.proof, _hasher());
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
            assertEq(keccak256(abi.encode(operation, guard)), beforeInputs, "caller memory changed");
        }
    }

    /// @dev Replay family-specific append merges, grafting each completed 256-leaf subtree once.
    function build(uint256 n, uint256 location, bytes memory operation, bool active)
        external
        pure
        returns (QMDBCase memory c)
    {
        c.operation = operation;
        c.proof.leaves = n;
        c.proof.location = location;
        bytes32[] memory chunks = new bytes32[]((n + 255) / 256);
        for (uint256 i; i < n; ++i) {
            if (i == location ? active : i % 3 != 0) {
                chunks[i / 256] |= bytes32(uint256(1) << (248 - ((i % 256) / 8) * 8 + i % 8));
            }
        }
        c.proof.chunk = chunks[location / 256];
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
                if (parent.width == 256) {
                    parent.digest = _hash(abi.encodePacked(chunks[parent.start / 256], parent.digest));
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
            if (nodes[i].width == 256) ++graftedChunks;
        }
        if (graftedChunks < n / 256) {
            c.proof.pending = _hash(abi.encodePacked(chunks[graftedChunks]));
            rootInput = abi.encodePacked(rootInput, c.proof.pending);
        }
        if (n % 256 != 0) {
            c.proof.partialDigest = _hash(abi.encodePacked(chunks[n / 256]));
            rootInput = abi.encodePacked(rootInput, uint64(n % 256), c.proof.partialDigest);
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
        c.proof.chunk ^= bytes32(uint256(1) << 128);
        assertFalse(exclusion ? this.checkedExclusion(c, key) : this.checked(c));
        c.proof.chunk ^= bytes32(uint256(1) << 128);
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
        c.proof.chunk = 0;
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
        string[] memory args = new string[](10);
        args[0] = string.concat(vm.projectRoot(), "/../target/release/commonware-sol-fuzz");
        args[1] = "qmdb";
        args[2] = "generate";
        args[3] = vm.toString(leaves);
        args[4] = vm.toString(location);
        args[5] = "71";
        args[6] = "--inactivity-floor";
        args[7] = vm.toString(floor);
        args[8] = "--family";
        args[9] = _mmb() ? "mmb" : "mmr";
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
                _ffi(args), (bytes32, uint256, uint256, uint256, bytes32, bytes32, bytes32, bytes32, bytes32[], bytes)
            );
        assertEq(c.proof.leaves, leaves);
        assertEq(c.proof.location, location);
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
        string[] memory args = new string[](metadata ? 12 : 11);
        args[0] = string.concat(vm.projectRoot(), "/../target/release/commonware-sol-fuzz");
        args[1] = "qmdb";
        args[2] = "exclude";
        args[3] = vm.toString(leaves);
        args[4] = vm.toString(location);
        args[5] = "71";
        args[6] = vm.toString(key);
        args[7] = "--family";
        args[8] = _mmb() ? "mmb" : "mmr";
        args[9] = "--mode";
        args[10] = mode;
        if (metadata) args[11] = "--metadata";
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
                (bytes32, uint256, uint256, uint256, bytes32, bytes32, bytes32, bytes32, bytes32[], bytes, bool)
            );
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
            assertTrue(this.verify(c));
            emit log_named_uint(
                string.concat(_group(_mmb() ? "QMDB" : "QMDBMMR"), "/", names[i]), vm.lastFrameGas().gasTotalUsed
            );
        }
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
