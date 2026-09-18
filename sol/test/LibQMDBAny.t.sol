// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.15;

import { HashTest } from "./Common.t.sol";
import { LibQMDBAny } from "../src/qmdb/LibQMDBAny.sol";

struct AnyCase {
    bytes32 root;
    bytes operation;
    LibQMDBAny.Proof proof;
}

struct AnyNode {
    bytes32 digest;
    uint256 start;
    uint256 width;
    uint256 left;
    uint256 right;
}

contract LibQMDBAnyTest is HashTest {
    /// @dev Select the delayed-merge MMB family.
    function _mmb() internal pure virtual returns (bool) {
        return true;
    }

    /// @dev Expose the selected family through a calldata proof entrypoint.
    function verify(AnyCase calldata c) external view returns (bool) {
        return _mmb()
            ? LibQMDBAny.verify(c.root, c.operation, c.proof, _hasher())
            : LibQMDBAny.verifyMMR(c.root, c.operation, c.proof, _hasher());
    }

    /// @dev Caller allocations and reusable scratch survive successful and rejected proofs.
    function checked(AnyCase calldata c) external view returns (bool valid) {
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
            bool result = _mmb()
                ? LibQMDBAny.verify(c.root, operation, c.proof, _hasher())
                : LibQMDBAny.verifyMMR(c.root, operation, c.proof, _hasher());
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

    /// @dev Append history supplies node positions and siblings independently of verifier geometry.
    function build(uint256 n, uint256 location, bytes memory operation) external pure returns (AnyCase memory c) {
        c.operation = operation;
        c.proof.leaves = n;
        c.proof.location = location;
        AnyNode[] memory nodes = new AnyNode[](2 * n);
        uint256[] memory peaks = new uint256[](n);
        uint256 count;
        uint256 position;
        for (uint256 i; i < n; ++i) {
            bytes memory encoded = i == location ? operation : abi.encodePacked(uint32(i), bytes1(0xa5));
            bytes32 leaf = _hash(abi.encodePacked(uint64(position), encoded));
            nodes[position] = AnyNode(leaf, i, 1, 0, 0);
            peaks[count++] = position++;
            for (uint256 j = count - 1; j > 0; --j) {
                uint256 left = peaks[j - 1];
                uint256 right = peaks[j];
                if (nodes[left].width != nodes[right].width) continue;
                AnyNode memory parent;
                parent.start = nodes[left].start;
                parent.width = nodes[left].width * 2;
                parent.left = left;
                parent.right = right;
                parent.digest = _hash(abi.encodePacked(uint64(position), nodes[left].digest, nodes[right].digest));
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
        bytes32 folded = nodes[peaks[count - 1]].digest;
        for (uint256 i = count - 1; i > 0; --i) {
            folded = _hash(abi.encodePacked(nodes[peaks[i - 1]].digest, folded));
        }
        c.root = _hash(abi.encodePacked(uint64(n), folded));
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
    function witnesses(AnyNode[] memory nodes, uint256 node, uint256 location, bytes32[] memory digests, uint256 length)
        internal
        pure
        returns (uint256)
    {
        AnyNode memory current = nodes[node];
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

    /// @dev Independently materialized trees cover peak and merge boundaries.
    function test_IndependentBoundaryTrees() public view {
        uint256[14] memory sizes = [uint256(1), 2, 3, 7, 8, 31, 32, 255, 256, 257, 383, 511, 512, 1023];
        for (uint256 i; i < sizes.length; ++i) {
            uint256 n = sizes[i];
            uint256[3] memory locations = [uint256(0), n / 2, n - 1];
            for (uint256 j; j < locations.length; ++j) {
                assertTrue(this.checked(this.build(n, locations[j], hex"00112233445566778899aabbcc")));
            }
        }
    }

    /// @dev Arbitrary operation bytes and their length are authenticated.
    function testFuzz_ArbitraryOperation(bytes memory operation, uint16 sizeSeed, uint16 locationSeed) public view {
        uint256 n = uint256(sizeSeed) % 640 + 1;
        AnyCase memory c = this.build(n, uint256(locationSeed) % n, operation);
        assertTrue(this.checked(c));
        c.operation = abi.encodePacked(operation, bytes1(0));
        assertFalse(this.checked(c), "operation length is not bound");
    }

    /// @dev Word boundaries and empty payloads preserve positioned hashing and caller memory.
    function test_OperationLengths() public view {
        uint256[11] memory lengths = [uint256(0), 1, 23, 24, 25, 31, 32, 33, 64, 97, 257];
        for (uint256 i; i < lengths.length; ++i) {
            bytes memory operation = new bytes(lengths[i]);
            for (uint256 j; j < operation.length; ++j) {
                operation[j] = bytes1(uint8(j));
            }
            assertTrue(this.checked(this.build(383, 127, operation)));
        }
    }

    /// @dev Commitments, exact witness consumption, and all coordinates are authenticated.
    function rejectMutations(AnyCase memory c) internal view {
        assertTrue(this.checked(c));
        c.root ^= bytes32(uint256(1));
        assertFalse(this.checked(c), "wrong root accepted");
        c.root ^= bytes32(uint256(1));
        bytes memory operation = c.operation;
        c.operation = abi.encodePacked(operation, bytes1(0));
        assertFalse(this.checked(c), "wrong operation accepted");
        c.operation = operation;
        if (operation.length != 0) {
            operation[operation.length / 2] ^= 0x01;
            assertFalse(this.checked(c), "modified operation byte accepted");
            operation[operation.length / 2] ^= 0x01;
        }
        uint256 inactive = c.proof.inactivePeaks;
        c.proof.inactivePeaks = type(uint256).max;
        assertFalse(this.checked(c), "oversized inactive count accepted");
        c.proof.inactivePeaks = inactive;
        for (uint256 i; i < c.proof.digests.length; ++i) {
            c.proof.digests[i] ^= bytes32(uint256(1));
            assertFalse(this.checked(c), "wrong witness accepted");
            c.proof.digests[i] ^= bytes32(uint256(1));
        }
        bytes32[] memory original = c.proof.digests;
        for (uint256 mode; mode < 2; ++mode) {
            if (mode == 1 && original.length == 0) continue;
            c.proof.digests = new bytes32[](mode == 0 ? original.length + 1 : original.length - 1);
            for (uint256 i; i < original.length && i < c.proof.digests.length; ++i) {
                c.proof.digests[i] = original[i];
            }
            assertFalse(this.checked(c), "wrong witness count accepted");
        }
        c.proof.digests = original;
        uint256 location = c.proof.location;
        if (c.proof.leaves > 1) {
            c.proof.location = (location + 1) % c.proof.leaves;
            assertFalse(this.checked(c), "wrong location accepted");
            c.proof.location = location;
        }
        ++c.proof.leaves;
        assertFalse(this.checked(c), "wrong leaf count accepted");
        --c.proof.leaves;
        c.proof.location = c.proof.leaves;
        assertFalse(this.checked(c), "out of bounds location accepted");
        c.proof.location = type(uint256).max;
        assertFalse(this.checked(c), "oversized location accepted");
        c.proof.location = 0;
        c.proof.leaves = 0;
        assertFalse(this.checked(c), "empty tree accepted");
        c.proof.leaves = (uint256(1) << 62) + (_mmb() ? 31 : 1);
        assertFalse(this.checked(c), "unsupported leaf count accepted");
        c.proof.leaves = type(uint256).max;
        assertFalse(this.checked(c), "oversized leaf count accepted");
    }

    /// @dev Mutations are rejected at both ends of trees with different peak shapes.
    function test_TamperedProofsAndBounds() public view {
        uint256[7] memory sizes = [uint256(1), 2, 8, 256, 257, 383, 639];
        for (uint256 i; i < sizes.length; ++i) {
            rejectMutations(this.build(sizes[i], 0, hex"010203"));
            if (sizes[i] > 1) rejectMutations(this.build(sizes[i], sizes[i] - 1, hex"010203"));
        }
    }

    /// @dev A root and proof from a distinct topology fail under the other family.
    function rejectOtherFamily(AnyCase calldata c) external view {
        bool valid = _mmb()
            ? LibQMDBAny.verifyMMR(c.root, c.operation, c.proof, _hasher())
            : LibQMDBAny.verify(c.root, c.operation, c.proof, _hasher());
        assertFalse(valid, "proof accepted by the other append family");
    }

    /// @dev Eager and delayed merges produce distinct authenticated histories.
    function test_CrossFamilyRejection() public view {
        uint256[3] memory sizes = [uint256(8), 256, 512];
        for (uint256 i; i < sizes.length; ++i) {
            AnyCase memory c = this.build(sizes[i], sizes[i] - 1, hex"010203");
            assertTrue(this.checked(c));
            this.rejectOtherFamily(c);
        }
    }

    /// @dev The oracle checks every emitted proof with Commonware's `qmdb::verify_proof`.
    function generate(uint256 leaves, uint256 location, uint256 floor, string memory history)
        internal
        returns (AnyCase memory c)
    {
        bool historical = bytes(history).length != 0;
        string[] memory args = new string[](historical ? 12 : 10);
        args[0] = string.concat(vm.projectRoot(), "/../target/release/commonware-sol-fuzz");
        args[1] = "qmdb";
        args[2] = "any";
        args[3] = vm.toString(leaves);
        args[4] = vm.toString(location);
        args[5] = "71";
        args[6] = "--inactivity-floor";
        args[7] = vm.toString(floor);
        args[8] = "--family";
        args[9] = _mmb() ? "mmb" : "mmr";
        if (historical) {
            args[10] = "--history";
            args[11] = history;
        }
        (c.root, c.proof.leaves, c.proof.location, c.proof.inactivePeaks, c.proof.digests, c.operation) =
            abi.decode(_ffi(args), (bytes32, uint256, uint256, uint256, bytes32[], bytes));
        assertEq(c.proof.leaves, leaves);
        assertEq(c.proof.location, location);
    }

    /// @dev Compare boundary proofs with the production Rust verifier.
    function test_DifferentialBoundaryTrees() public {
        uint256[10] memory sizes = [uint256(1), 2, 7, 8, 255, 256, 257, 383, 512, 1023];
        for (uint256 i; i < sizes.length; ++i) {
            assertTrue(this.checked(generate(sizes[i], 0, 0, "")));
            if (sizes[i] > 1) assertTrue(this.checked(generate(sizes[i], sizes[i] - 1, 0, "")));
        }
    }

    /// @dev Random locations and inactivity floors exercise Rust proof geometry.
    function testFuzz_DifferentialTrees(uint16 sizeSeed, uint16 locationSeed, uint16 floorSeed) public {
        uint256 n = uint256(sizeSeed) % 1536 + 1;
        uint256 floor = uint256(floorSeed) % n;
        uint256 location = floor + uint256(locationSeed) % (n - floor);
        AnyCase memory c = generate(n, location, floor, "");
        assertTrue(this.checked(c));
        c.operation = abi.encodePacked(c.operation, bytes1(0));
        assertFalse(this.checked(c), "modified oracle operation accepted");
    }

    /// @dev Inactive peak counts are committed by the root and affect witness ordering.
    function test_DifferentialInactivePeaks() public {
        uint256[4] memory floors = [uint256(512), 768, 1024, 1280];
        for (uint256 i; i < floors.length; ++i) {
            uint256 n = i < 2 ? 1023 : 1535;
            assertTrue(this.checked(generate(n, floors[i], floors[i], "")));
            AnyCase memory c = generate(n, n - 1, floors[i], "");
            assertGt(c.proof.inactivePeaks, 0, "fixture has no inactive peaks");
            rejectMutations(c);
            c = generate(n, n - 1, floors[i], "");
            c.proof.inactivePeaks = 0;
            assertFalse(this.checked(c), "inactive boundary is not bound");
        }
    }

    /// @dev Later updates and deletion leave the first encoded update in the authenticated history.
    function test_DifferentialHistoricalUpdates() public {
        uint256[2] memory sizes = [uint256(8), 257];
        for (uint256 i; i < sizes.length; ++i) {
            AnyCase memory updated = generate(sizes[i], 0, 0, "updated");
            AnyCase memory deleted = generate(sizes[i], 0, 0, "deleted");
            assertEq(updated.operation, deleted.operation, "historical update differs");
            assertTrue(this.checked(updated), "overwritten update rejected");
            assertTrue(this.checked(deleted), "deleted key's historical update rejected");
            assertTrue(updated.root != deleted.root, "delete did not alter history");
        }
    }
}

contract LibQMDBAnySha256Test is LibQMDBAnyTest {
    /// @dev Run the inherited cases through the SHA256 precompile.
    function _hasher() internal pure override returns (address) {
        return address(2);
    }
}

contract LibQMDBAnyMMRTest is LibQMDBAnyTest {
    /// @dev Select the eagerly merged MMR family.
    function _mmb() internal pure override returns (bool) {
        return false;
    }
}

contract LibQMDBAnyMMRSha256Test is LibQMDBAnyMMRTest {
    /// @dev Run the inherited cases through the SHA256 precompile.
    function _hasher() internal pure override returns (address) {
        return address(2);
    }
}
