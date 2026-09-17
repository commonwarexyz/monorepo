// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.15;

import { HashTest } from "./Common.t.sol";
import { LibQMDB } from "../src/qmdb/LibQMDB.sol";

/// @dev Operations remain opaque byte strings.
struct QMDBCase {
    bytes32 root;
    bytes operation;
    LibQMDB.Proof proof;
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

contract LibQMDBTest is HashTest {
    /// @dev Expose the calldata proof entrypoint for tests and gas measurements.
    function verify(QMDBCase calldata c) external view returns (bool) {
        return LibQMDB.verify(c.root, c.operation, c.proof, _hasher());
    }

    /// @dev Check caller allocations, dirty scratch, and subsequent allocations on every exit path.
    function checked(QMDBCase calldata c) external view returns (bool valid) {
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
            bool result = LibQMDB.verify(c.root, operation, c.proof, _hasher());
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

    /// @dev Replay delayed append merges, grafting each completed 256-leaf subtree once.
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
                break;
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
        uint256[15] memory sizes = [uint256(1), 2, 255, 256, 257, 382, 383, 511, 512, 638, 639, 767, 1023, 1535, 2047];
        for (uint256 i; i < sizes.length; ++i) {
            uint256 n = sizes[i];
            uint256[4] memory locations = [uint256(0), n / 2, n > 256 ? 255 : n - 1, n - 1];
            for (uint256 j; j < locations.length; ++j) {
                assertTrue(this.checked(this.build(n, locations[j], hex"00112233445566778899aabbcc", true)));
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
        assertTrue(this.checked(c));
        c.root ^= bytes32(uint256(1));
        assertFalse(this.checked(c));
        c.root ^= bytes32(uint256(1));
        c.proof.opsRoot ^= bytes32(uint256(1));
        assertFalse(this.checked(c));
        c.proof.opsRoot ^= bytes32(uint256(1));
        c.proof.pending ^= bytes32(uint256(1));
        assertFalse(this.checked(c));
        c.proof.pending ^= bytes32(uint256(1));
        c.proof.partialDigest ^= bytes32(uint256(1));
        assertFalse(this.checked(c));
        c.proof.partialDigest ^= bytes32(uint256(1));
        c.proof.chunk ^= bytes32(uint256(1) << 128);
        assertFalse(this.checked(c));
        c.proof.chunk ^= bytes32(uint256(1) << 128);
        for (uint256 i; i < c.proof.digests.length; ++i) {
            c.proof.digests[i] ^= bytes32(uint256(1));
            assertFalse(this.checked(c));
            c.proof.digests[i] ^= bytes32(uint256(1));
        }
        bytes32[] memory original = c.proof.digests;
        c.proof.digests = new bytes32[](original.length + 1);
        for (uint256 i; i < original.length; ++i) {
            c.proof.digests[i] = original[i];
        }
        assertFalse(this.checked(c), "trailing witness accepted");
        if (original.length != 0) {
            c.proof.digests = new bytes32[](original.length - 1);
            for (uint256 i; i < c.proof.digests.length; ++i) {
                c.proof.digests[i] = original[i];
            }
            assertFalse(this.checked(c), "missing witness accepted");
        }
        c.proof.digests = original;
        if (c.proof.leaves > 1) {
            uint256 location = c.proof.location;
            c.proof.location = (location + 1) % c.proof.leaves;
            assertFalse(this.checked(c), "wrong location accepted");
            c.proof.location = location;
        }
        ++c.proof.leaves;
        assertFalse(this.checked(c));
        --c.proof.leaves;
        c.proof.location = c.proof.leaves;
        assertFalse(this.checked(c));
        c.proof.location = type(uint256).max;
        assertFalse(this.checked(c));
        c.proof.location = 0;
        c.proof.leaves = 0;
        assertFalse(this.checked(c));
        c.proof.leaves = (uint256(1) << 62) + 31;
        assertFalse(this.checked(c));
        c.proof.leaves = type(uint256).max;
        assertFalse(this.checked(c));
    }

    /// @dev Exercise absent, pending, partial, and combined witness shapes on rejection paths.
    function test_TamperedProofsAndBounds() public view {
        uint256[6] memory sizes = [uint256(1), 256, 257, 383, 512, 639];
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

    /// @dev Decode the Rust oracle's flat ABI tuple without imposing an operation type.
    function generate(uint256 leaves, uint256 location, uint256 floor) internal returns (QMDBCase memory c) {
        string[] memory args = new string[](8);
        args[0] = string.concat(vm.projectRoot(), "/../target/release/commonware-sol-fuzz");
        args[1] = "qmdb";
        args[2] = "generate";
        args[3] = vm.toString(leaves);
        args[4] = vm.toString(location);
        args[5] = "71";
        args[6] = "--inactivity-floor";
        args[7] = vm.toString(floor);
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
        uint256[14] memory sizes = [uint256(1), 2, 255, 256, 257, 382, 383, 511, 512, 638, 639, 767, 1023, 2047];
        for (uint256 i; i < sizes.length; ++i) {
            assertTrue(this.checked(generate(sizes[i], 0, 0)));
            assertTrue(this.checked(generate(sizes[i], sizes[i] - 1, 0)));
            if (sizes[i] > 256) assertTrue(this.checked(generate(sizes[i], 256, 0)));
        }
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

    /// @dev Measure only the verifier call for grafted, pending, and partial target chunks.
    function test_Gas() public {
        uint256[3] memory locations = [uint256(17), 256, 637];
        string[3] memory names = [string("grafted"), "pending", "partial"];
        for (uint256 i; i < locations.length; ++i) {
            QMDBCase memory c = this.build(638, locations[i], new bytes(97), true);
            assertTrue(this.verify(c));
            emit log_named_uint(string.concat(_group("QMDB"), "/", names[i]), vm.lastFrameGas().gasTotalUsed);
        }
    }
}

contract LibQMDBSha256Test is LibQMDBTest {
    /// @dev Run the same compatibility and rejection cases through the SHA-256 precompile.
    function _hasher() internal pure override returns (address) {
        return address(2);
    }
}
