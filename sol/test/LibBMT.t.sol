// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.15;

import { HashSelection, HashTest } from "./Common.t.sol";
import { LibBMT } from "../src/merkle/LibBMT.sol";

/// @dev External entry points isolate gas measurements and expose calldata slices.
contract BMTHarness is HashSelection {
    /// @dev Verify a memory single proof.
    function single(bytes32 root, uint256 leaves, uint256 index, bytes32 element, bytes32[] memory proof)
        external
        view
        returns (bool)
    {
        return LibBMT.verify(root, leaves, index, element, proof, _hasher());
    }

    /// @dev Verify a calldata single proof.
    function singleCalldata(bytes32 root, uint256 leaves, uint256 index, bytes32 element, bytes32[] calldata proof)
        external
        view
        returns (bool)
    {
        return LibBMT.verifyCalldata(root, leaves, index, element, proof, _hasher());
    }

    /// @dev Verify a memory range proof.
    function range(bytes32 root, uint256 leaves, uint256 start, bytes32[] memory elements, bytes32[] memory proof)
        external
        view
        returns (bool)
    {
        return LibBMT.verifyRange(root, leaves, start, elements, proof, _hasher());
    }

    /// @dev Verify a calldata range proof.
    function rangeCalldata(
        bytes32 root,
        uint256 leaves,
        uint256 start,
        bytes32[] calldata elements,
        bytes32[] calldata proof
    ) external view returns (bool) {
        return LibBMT.verifyRangeCalldata(root, leaves, start, elements, proof, _hasher());
    }

    /// @dev Verify a memory sparse proof.
    function multi(
        bytes32 root,
        uint256 leaves,
        uint256[] memory indices,
        bytes32[] memory elements,
        bytes32[] memory proof
    ) external view returns (bool) {
        return LibBMT.verifyMulti(root, leaves, indices, elements, proof, _hasher());
    }

    /// @dev Verify a calldata sparse proof.
    function multiCalldata(
        bytes32 root,
        uint256 leaves,
        uint256[] calldata indices,
        bytes32[] calldata elements,
        bytes32[] calldata proof
    ) external view returns (bool) {
        return LibBMT.verifyMultiCalldata(root, leaves, indices, elements, proof, _hasher());
    }
}

contract LibBMTTest is HashTest {
    struct Case {
        bytes32 root;
        uint256 leaves;
        uint256 start;
        uint256[] indices;
        bytes32[] elements;
        bytes32[] proof;
    }

    BMTHarness internal harness = new BMTHarness();

    /// @dev Build an independent complete tree and collect missing siblings by level.
    function fixture(uint256 size, uint256[] memory indices, bytes32 seed) internal pure returns (Case memory c) {
        c.leaves = size;
        c.indices = indices;
        c.start = indices.length == 0 ? 0 : indices[0];
        c.elements = new bytes32[](indices.length);
        bytes32[] memory nodes = new bytes32[](size);
        bool[] memory selected = new bool[](size);
        c.proof = new bytes32[](size * 2);
        for (uint256 i; i < size; ++i) {
            bytes32 element = keccak256(abi.encode(seed, i));
            nodes[i] = _hash(abi.encodePacked(uint32(i), element));
        }
        for (uint256 i; i < indices.length; ++i) {
            c.elements[i] = keccak256(abi.encode(seed, indices[i]));
            selected[indices[i]] = true;
        }
        uint256 used;
        for (uint256 width = size; width > 1; width = (width + 1) / 2) {
            for (uint256 i; i < width; i += 2) {
                uint256 right = i + 1 < width ? i + 1 : i;
                if (right != i && selected[i] != selected[right]) {
                    c.proof[used++] = selected[i] ? nodes[right] : nodes[i];
                }
                nodes[i / 2] = _hash(abi.encodePacked(nodes[i], nodes[right]));
                selected[i / 2] = selected[i] || selected[right];
            }
        }
        c.root = _hash(abi.encodePacked(uint32(size), size == 0 ? _hash("") : nodes[0]));
        bytes32[] memory proof = c.proof;
        assembly ("memory-safe") { mstore(proof, used) }
    }

    /// @dev Create consecutive indices.
    function consecutive(uint256 start, uint256 count) internal pure returns (uint256[] memory result) {
        result = new uint256[](count);
        for (uint256 i; i < count; ++i) {
            result[i] = start + i;
        }
    }

    /// @dev Exercise memory and calldata variants with identical arguments.
    function verifyCase(Case memory c, uint256 mode) internal view returns (bool result) {
        if (mode == 0) {
            result = harness.single(c.root, c.leaves, c.start, c.elements[0], c.proof);
            assertEq(result, harness.singleCalldata(c.root, c.leaves, c.start, c.elements[0], c.proof));
        } else if (mode == 1) {
            result = harness.range(c.root, c.leaves, c.start, c.elements, c.proof);
            assertEq(result, harness.rangeCalldata(c.root, c.leaves, c.start, c.elements, c.proof));
        } else {
            result = harness.multi(c.root, c.leaves, c.indices, c.elements, c.proof);
            assertEq(result, harness.multiCalldata(c.root, c.leaves, c.indices, c.elements, c.proof));
        }
    }

    /// @dev Cover empty roots and strict empty range bounds.
    function test_Empty() public view {
        Case memory c = fixture(0, new uint256[](0), 0);
        assertEq(
            c.root,
            _hasher() == address(0)
                ? bytes32(0x784a1ebc13dd1197cb82f60cccc7608f891abcef018f1a85e484ebcb61a31d73)
                : sha256(abi.encodePacked(uint32(0), sha256("")))
        );
        assertTrue(verifyCase(c, 1));
        assertTrue(verifyCase(c, 2));
        c.start = 1;
        assertFalse(verifyCase(c, 1));
        c.start = 0;
        c.root ^= bytes32(uint256(1));
        assertFalse(verifyCase(c, 1));
        assertFalse(verifyCase(c, 2));
        c = fixture(1, new uint256[](0), 0);
        assertFalse(verifyCase(c, 1));
        assertFalse(verifyCase(c, 2));
        assertFalse(harness.single(c.root, 0, 0, 0, c.proof));
        assertFalse(harness.singleCalldata(c.root, 0, 0, 0, c.proof));
        c = fixture(0, new uint256[](0), 0);
        c.proof = new bytes32[](1);
        assertFalse(verifyCase(c, 1));
        assertFalse(verifyCase(c, 2));
    }

    /// @dev Assert literal single-leaf hashing and odd duplication without a witness.
    function test_KnownRootsAndOddDuplication() public view {
        bytes32 element = bytes32(uint256(42));
        bytes32 root = _hash(abi.encodePacked(uint32(1), _hash(abi.encodePacked(uint32(0), element))));
        assertEq(
            root,
            _hasher() == address(0)
                ? bytes32(0x1f2bc41fa71f825a0e9c8d2a4dfe9dbb6020f92e176931ec2b170cea60ad768c)
                : sha256(abi.encodePacked(uint32(1), sha256(abi.encodePacked(uint32(0), element))))
        );
        assertTrue(harness.single(root, 1, 0, element, new bytes32[](0)));
        for (uint256 n = 1; n <= 17; ++n) {
            Case memory c = fixture(n, consecutive(n - 1, 1), 0);
            assertTrue(verifyCase(c, 0));
            assertTrue(verifyCase(c, 1));
            assertTrue(verifyCase(c, 2));
            if (n == 3 || n == 5 || n == 9 || n == 17) assertEq(c.proof.length, 1);
        }
    }

    /// @dev Cover every small contiguous boundary and complete tree.
    function test_SmallRanges() public view {
        for (uint256 n = 1; n <= 12; ++n) {
            for (uint256 start; start < n; ++start) {
                for (uint256 count = 1; count <= n - start; ++count) {
                    Case memory c = fixture(n, consecutive(start, count), 0);
                    assertTrue(verifyCase(c, 1));
                    assertTrue(verifyCase(c, 2));
                }
            }
        }
    }

    /// @dev Fuzz contiguous reconstruction including all odd-level shapes.
    function testFuzz_Range(uint8 n, uint8 s, uint8 len, bytes32 seed) public view {
        uint256 size = uint256(n) + 1;
        uint256 start = uint256(s) % size;
        uint256 count = 1 + uint256(len) % (size - start);
        Case memory c = fixture(size, consecutive(start, count), seed);
        assertTrue(verifyCase(c, 1));
        assertTrue(verifyCase(c, 2));
    }

    /// @dev Fuzz unsorted sparse pairs while preserving each element's index.
    function testFuzz_Sparse(uint8 n, bytes32 seed) public view {
        uint256 size = uint256(n) + 1;
        uint256[] memory indices = new uint256[]((size + 2) / 3);
        for (uint256 i; i < indices.length; ++i) {
            indices[i] = (indices.length - 1 - i) * 3;
        }
        Case memory c = fixture(size, indices, seed);
        assertTrue(verifyCase(c, 2));
        if (indices.length > 1) {
            c.indices[1] = c.indices[0];
            assertFalse(verifyCase(c, 2));
        }
    }

    /// @dev Reject oversized counts, overflowed bounds, mismatched pairs and invalid positions.
    function test_MalformedBounds() public view {
        Case memory c = fixture(3, consecutive(1, 1), 0);
        for (uint256 mode; mode < 3; ++mode) {
            c.leaves = uint256(type(uint32).max) + 1;
            assertFalse(verifyCase(c, mode));
            c.leaves = type(uint256).max;
            assertFalse(verifyCase(c, mode));
            c.leaves = 3;
            c.start = type(uint256).max;
            c.indices[0] = c.start;
            assertFalse(verifyCase(c, mode));
            c.start = 3;
            c.indices[0] = 3;
            assertFalse(verifyCase(c, mode));
            c.start = 1;
            c.indices[0] = 1;
        }
        c.indices = new uint256[](0);
        assertFalse(verifyCase(c, 2));
        c = fixture(3, consecutive(0, 3), 0);
        c.start = 1;
        assertFalse(verifyCase(c, 1));
    }

    /// @dev Reject missing, extra, reordered and corrupted witnesses in every mode.
    function test_ProofMutations() public view {
        for (uint256 mode; mode < 3; ++mode) {
            Case memory c = fixture(13, consecutive(3, 1), 0);
            assertTrue(verifyCase(c, mode));
            bytes32 saved = c.proof[0];
            c.proof[0] ^= bytes32(uint256(1));
            assertFalse(verifyCase(c, mode));
            c.proof[0] = saved;
            (c.proof[0], c.proof[1]) = (c.proof[1], c.proof[0]);
            assertFalse(verifyCase(c, mode));
            (c.proof[0], c.proof[1]) = (c.proof[1], c.proof[0]);
            bytes32[] memory proof = c.proof;
            assembly ("memory-safe") { mstore(proof, sub(mload(proof), 1)) }
            assertFalse(verifyCase(c, mode));
            c = fixture(13, consecutive(3, 1), 0);
            bytes32[] memory extra = new bytes32[](c.proof.length + 1);
            for (uint256 i; i < c.proof.length; ++i) {
                extra[i] = c.proof[i];
            }
            c.proof = extra;
            assertFalse(verifyCase(c, mode));
            c = fixture(13, consecutive(3, 1), 0);
            c.root ^= bytes32(uint256(1));
            assertFalse(verifyCase(c, mode));
            c = fixture(13, consecutive(3, 1), 0);
            c.elements[0] ^= bytes32(uint256(1));
            assertFalse(verifyCase(c, mode));
        }
    }

    /// @dev Check input immutability, zero slot, private scratch cleanup and subsequent allocations.
    function checked(Case calldata c, uint256 mode, bool cd) external view returns (bool result) {
        uint256[] memory indices = c.indices;
        bytes32[] memory elements = c.elements;
        bytes32[] memory proof = c.proof;
        bytes32 beforeHash = keccak256(abi.encode(indices, elements, proof));
        uint256 beforePointer;
        assembly ("memory-safe") { beforePointer := mload(0x40) }
        uint256 scratchEnd = beforePointer;
        if (mode == 1 && c.leaves <= type(uint32).max && c.start <= c.leaves && elements.length <= c.leaves - c.start) {
            scratchEnd += elements.length * 32;
        }
        if (mode == 0) {
            result = cd
                ? LibBMT.verifyCalldata(c.root, c.leaves, c.start, elements[0], c.proof, _hasher())
                : LibBMT.verify(c.root, c.leaves, c.start, elements[0], proof, _hasher());
        } else if (mode == 1) {
            result = cd
                ? LibBMT.verifyRangeCalldata(c.root, c.leaves, c.start, c.elements, c.proof, _hasher())
                : LibBMT.verifyRange(c.root, c.leaves, c.start, elements, proof, _hasher());
        } else {
            result = cd
                ? LibBMT.verifyMultiCalldata(c.root, c.leaves, c.indices, c.elements, c.proof, _hasher())
                : LibBMT.verifyMulti(c.root, c.leaves, indices, elements, proof, _hasher());
        }
        assembly ("memory-safe") {
            if mload(0x60) { revert(0, 0) }
            let afterPointer := mload(0x40)
            if or(lt(afterPointer, beforePointer), and(afterPointer, 31)) { revert(0, 0) }
            if lt(scratchEnd, afterPointer) { scratchEnd := afterPointer }
            for { let p := beforePointer } lt(p, scratchEnd) { p := add(p, 32) } {
                if mload(p) { revert(0, 0) }
            }
        }
        require(beforeHash == keccak256(abi.encode(indices, elements, proof)), "input mutation");
        bytes32[] memory afterAllocation = new bytes32[](7);
        for (uint256 i; i < afterAllocation.length; ++i) {
            require(afterAllocation[i] == 0, "dirty allocation");
        }
    }

    /// @dev Cover success and failure exits after partial reconstruction or sorting.
    function test_MemoryExitPaths() public view {
        for (uint256 mode; mode < 3; ++mode) {
            for (uint256 location; location < 2; ++location) {
                Case memory c = fixture(7, consecutive(2, 1), 0);
                assertTrue(this.checked(c, mode, location != 0));
                c.proof = new bytes32[](0);
                assertFalse(this.checked(c, mode, location != 0));
                c = fixture(7, consecutive(2, 1), 0);
                c.root = 0;
                assertFalse(this.checked(c, mode, location != 0));
                c.leaves = type(uint256).max;
                assertFalse(this.checked(c, mode, location != 0));
            }
        }
        Case memory sparse = fixture(7, consecutive(1, 4), 0);
        (sparse.indices[0], sparse.indices[3]) = (sparse.indices[3], sparse.indices[0]);
        (sparse.elements[0], sparse.elements[3]) = (sparse.elements[3], sparse.elements[0]);
        assertTrue(this.checked(sparse, 2, false));
        assertTrue(this.checked(sparse, 2, true));
        sparse.indices[1] = sparse.indices[0];
        assertFalse(this.checked(sparse, 2, false));
        assertFalse(this.checked(sparse, 2, true));
    }

    /// @dev Shared element and proof arrays remain readable and unchanged.
    function test_AliasedInputs() public view {
        bytes32[] memory shared = new bytes32[](1);
        shared[0] = _hash(abi.encodePacked(uint32(1), bytes32(uint256(42))));
        bytes32 before = shared[0];
        bytes32 left = _hash(abi.encodePacked(uint32(0), shared[0]));
        bytes32 root = _hash(abi.encodePacked(uint32(2), _hash(abi.encodePacked(left, shared[0]))));
        uint256[] memory indices = consecutive(0, 1);
        assertTrue(LibBMT.verify(root, 2, 0, shared[0], shared, _hasher()));
        assertTrue(LibBMT.verifyRange(root, 2, 0, shared, shared, _hasher()));
        assertTrue(LibBMT.verifyMulti(root, 2, indices, shared, shared, _hasher()));
        assertEq(shared[0], before);
    }

    /// @dev Fuzz memory ownership across every verifier and both input locations.
    function testFuzz_MemorySafety(uint8 n, uint8 s, uint8 len, bytes32 seed, bool malformed) public view {
        uint256 size = uint256(n) + 1;
        uint256 start = uint256(s) % size;
        for (uint256 mode; mode < 3; ++mode) {
            uint256 count = mode == 0 ? 1 : 1 + uint256(len) % (size - start);
            Case memory c = fixture(size, consecutive(start, count), seed);
            if (mode == 2 && count > 1) {
                (c.indices[0], c.indices[count - 1]) = (c.indices[count - 1], c.indices[0]);
                (c.elements[0], c.elements[count - 1]) = (c.elements[count - 1], c.elements[0]);
            }
            if (malformed) c.root ^= bytes32(uint256(1));
            assertEq(this.checked(c, mode, false), !malformed);
            assertEq(this.checked(c, mode, true), !malformed);
        }
    }

    /// @dev Exercise empty and invalid sparse-index exits in the memory harness.
    function test_MemoryEmptyAndBounds() public view {
        Case memory c = fixture(0, new uint256[](0), 0);
        for (uint256 mode = 1; mode < 3; ++mode) {
            assertTrue(this.checked(c, mode, false));
            assertTrue(this.checked(c, mode, true));
        }
        c = fixture(5, consecutive(1, 2), 0);
        c.indices[1] = 5;
        assertFalse(this.checked(c, 2, false));
        assertFalse(this.checked(c, 2, true));
        c.indices = new uint256[](0);
        assertFalse(this.checked(c, 2, false));
        assertFalse(this.checked(c, 2, true));
    }

    /// @dev Verify arrays whose calldata offsets begin after unrelated sentinels.
    function sliced(Case calldata c, uint256[] calldata indices, bytes32[] calldata elements, bytes32[] calldata proof)
        external
        view
        returns (bool)
    {
        return LibBMT.verifyCalldata(c.root, c.leaves, c.start, elements[1], proof[1:proof.length - 1], _hasher())
            && LibBMT.verifyRangeCalldata(
            c.root, c.leaves, c.start, elements[1:elements.length - 1], proof[1:proof.length - 1], _hasher()
        )
            && LibBMT.verifyMultiCalldata(
            c.root,
            c.leaves,
            indices[1:indices.length - 1],
            elements[1:elements.length - 1],
            proof[1:proof.length - 1],
            _hasher()
        );
    }

    /// @dev Fuzz sliced proof pointers and nonzero leaf positions.
    function testFuzz_CalldataSlices(uint8 n, uint8 index, bytes32 seed) public view {
        uint256 size = uint256(n) + 1;
        Case memory c = fixture(size, consecutive(uint256(index) % size, 1), seed);
        uint256[] memory indices = new uint256[](3);
        bytes32[] memory elements = new bytes32[](3);
        bytes32[] memory proof = new bytes32[](c.proof.length + 2);
        indices[1] = c.start;
        elements[1] = c.elements[0];
        proof[0] = bytes32(uint256(123));
        proof[proof.length - 1] = bytes32(uint256(456));
        for (uint256 i; i < c.proof.length; ++i) {
            proof[i + 1] = c.proof[i];
        }
        assertTrue(this.sliced(c, indices, elements, proof));
    }

    /// @dev Measure isolated calls with valid single, range and unsorted sparse proofs.
    function testGas_Verification() public {
        Case memory c = fixture(256, consecutive(127, 1), 0);
        assertTrue(harness.single(c.root, c.leaves, c.start, c.elements[0], c.proof));
        vm.snapshotGasLastFrame(_group("BMT"), "single-256");
        assertTrue(harness.singleCalldata(c.root, c.leaves, c.start, c.elements[0], c.proof));
        vm.snapshotGasLastFrame(_group("BMT"), "single-256-calldata");
        c = fixture(256, consecutive(93, 32), 0);
        assertTrue(harness.range(c.root, c.leaves, c.start, c.elements, c.proof));
        vm.snapshotGasLastFrame(_group("BMT"), "range-256-32");
        assertTrue(harness.rangeCalldata(c.root, c.leaves, c.start, c.elements, c.proof));
        vm.snapshotGasLastFrame(_group("BMT"), "range-256-32-calldata");
        uint256[] memory indices = new uint256[](16);
        for (uint256 i; i < 16; ++i) {
            indices[i] = 255 - i * 16;
        }
        c = fixture(256, indices, 0);
        assertTrue(harness.multi(c.root, c.leaves, c.indices, c.elements, c.proof));
        vm.snapshotGasLastFrame(_group("BMT"), "multi-256-16");
        assertTrue(harness.multiCalldata(c.root, c.leaves, c.indices, c.elements, c.proof));
        vm.snapshotGasLastFrame(_group("BMT"), "multi-256-16-calldata");
    }

    /// @dev Invoke Commonware's actual BMT generator.
    function generate(uint256 leaves, uint256 start, uint256 count, uint64 seed, bool synthetic)
        internal
        returns (Case memory c)
    {
        string[] memory args = new string[](synthetic ? 9 : 11);
        args[0] = string.concat(vm.projectRoot(), "/../target/release/commonware-sol-fuzz");
        args[1] = "bmt";
        args[2] = synthetic ? "synthetic" : "generate";
        args[3] = "--leaves";
        args[4] = vm.toString(leaves);
        args[5] = synthetic ? "--index" : "--start";
        args[6] = vm.toString(start);
        if (!synthetic) {
            args[7] = "--count";
            args[8] = vm.toString(count);
        }
        args[args.length - 2] = "--seed";
        args[args.length - 1] = vm.toString(uint256(seed));
        return decodeCase(_ffi(args));
    }

    /// @dev Decode the flat ABI tuple shared by the generator and Rust checker.
    function decodeCase(bytes memory encoded) internal pure returns (Case memory c) {
        (c.root, c.leaves, c.start, c.indices, c.elements, c.proof) =
            abi.decode(encoded, (bytes32, uint256, uint256, uint256[], bytes32[], bytes32[]));
    }

    /// @dev Compare both Solidity input locations with the Rust verification result.
    function compare(Case memory c, uint256 mode) internal returns (bool result) {
        string[] memory args = new string[](7);
        args[0] = string.concat(vm.projectRoot(), "/../target/release/commonware-sol-fuzz");
        args[1] = "bmt";
        args[2] = "check";
        args[3] = "--mode";
        args[4] = mode == 0 ? "single" : mode == 1 ? "range" : "multi";
        args[5] = "--abi-hex";
        args[6] = vm.toString(abi.encode(c.root, c.leaves, c.start, c.indices, c.elements, c.proof));
        result = verifyCase(c, mode);
        assertEq(result, abi.decode(_ffi(args), (bool)), "Rust disagreement");
    }

    /// @dev Differentially fuzz real range proofs and a corrupted witness or element.
    function testFuzz_DifferentialRange(uint8 n, uint8 s, uint8 len, uint64 seed) public {
        uint256 size = uint256(n) + 1;
        uint256 start = uint256(s) % size;
        Case memory c = generate(size, start, 1 + uint256(len) % (size - start), seed, false);
        assertTrue(compare(c, 1));
        assertTrue(compare(c, 2));
        c.elements[0] ^= bytes32(uint256(1));
        assertFalse(compare(c, 1));
    }

    /// @dev Differentially fuzz single-leaf proofs from bounded complete trees.
    function testFuzz_DifferentialSingle(uint8 n, uint8 index, uint64 seed) public {
        uint256 size = uint256(n) + 1;
        Case memory c = generate(size, uint256(index) % size, 1, seed, false);
        assertTrue(compare(c, 0));
        c.proof = new bytes32[](0);
        compare(c, 0);
    }

    /// @dev Differentially fuzz sparse proofs with unsorted indices and duplicate rejection.
    function testFuzz_DifferentialMulti(uint8 n, uint64 seed) public {
        uint256 size = uint256(n) + 1;
        string memory csv = vm.toString(size - 1);
        for (uint256 i = size - 1; i > 2; i -= 3) {
            csv = string.concat(csv, ",", vm.toString(i - 3));
        }
        string[] memory args = new string[](9);
        args[0] = string.concat(vm.projectRoot(), "/../target/release/commonware-sol-fuzz");
        args[1] = "bmt";
        args[2] = "generate-multi";
        args[3] = "--leaves";
        args[4] = vm.toString(size);
        args[5] = "--indices";
        args[6] = csv;
        args[7] = "--seed";
        args[8] = vm.toString(uint256(seed));
        Case memory c = decodeCase(_ffi(args));
        assertTrue(compare(c, 2));
        if (c.proof.length > 1) {
            (c.proof[0], c.proof[1]) = (c.proof[1], c.proof[0]);
            assertFalse(compare(c, 2));
            (c.proof[0], c.proof[1]) = (c.proof[1], c.proof[0]);
        }
        if (c.proof.length > 0) {
            bytes32[] memory proof = c.proof;
            assembly ("memory-safe") { mstore(proof, sub(mload(proof), 1)) }
            assertFalse(compare(c, 2));
            assembly ("memory-safe") { mstore(proof, add(mload(proof), 1)) }
        }
        if (c.indices.length > 1) {
            c.indices[1] = c.indices[0];
            assertFalse(compare(c, 2));
        }
    }

    /// @dev Reach the full 32-level domain without constructing billions of leaves.
    function test_DifferentialMaximumSize() public {
        uint256 size = type(uint32).max;
        for (uint256 i; i < 3; ++i) {
            Case memory c = generate(size, i == 0 ? 0 : i == 1 ? size / 2 : size - 1, 1, 7, true);
            for (uint256 mode; mode < 3; ++mode) {
                assertTrue(compare(c, mode));
            }
        }
    }

    /// @dev Compare empty proofs and out-of-domain integer bounds with Rust.
    function test_DifferentialEmptyAndBounds() public {
        Case memory c = generate(0, 0, 0, 0, false);
        assertTrue(compare(c, 1));
        assertTrue(compare(c, 2));
        c.start = 1;
        assertFalse(compare(c, 1));
        c = generate(3, 1, 1, 0, false);
        c.leaves = type(uint256).max;
        for (uint256 mode; mode < 3; ++mode) {
            assertFalse(compare(c, mode));
        }
    }

    /// @dev Differentially fuzz arbitrary invalid values with bounded witness allocation.
    function testFuzz_DifferentialMalformed(uint256 leaves, uint256 start, bytes32 root, bytes32 seed, uint8 shape)
        public
    {
        uint256 count = uint256(shape) % 8;
        Case memory c;
        c.root = root;
        c.leaves = leaves;
        c.start = start;
        c.indices = new uint256[](count);
        c.elements = new bytes32[](count);
        c.proof = new bytes32[](uint256(shape) / 8);
        for (uint256 i; i < count; ++i) {
            c.indices[i] = uint256(keccak256(abi.encode(seed, i)));
            c.elements[i] = keccak256(abi.encode(i, seed));
        }
        for (uint256 i; i < c.proof.length; ++i) {
            c.proof[i] = keccak256(abi.encode(seed, "proof", i));
        }
        compare(c, 1);
        compare(c, 2);
        if (count == 1) compare(c, 0);
    }

    /// @dev Compare missing, extra, reordered and malformed bounds against the actual Rust verifier.
    function test_DifferentialMutations() public {
        for (uint256 mode; mode < 3; ++mode) {
            Case memory c = generate(13, 3, 1, 9, false);
            assertTrue(compare(c, mode));
            (c.proof[0], c.proof[1]) = (c.proof[1], c.proof[0]);
            assertFalse(compare(c, mode));
            (c.proof[0], c.proof[1]) = (c.proof[1], c.proof[0]);
            bytes32[] memory proof = c.proof;
            assembly ("memory-safe") { mstore(proof, sub(mload(proof), 1)) }
            assertFalse(compare(c, mode));
            c = generate(13, 3, 1, 9, false);
            bytes32[] memory extra = new bytes32[](c.proof.length + 1);
            for (uint256 i; i < c.proof.length; ++i) {
                extra[i] = c.proof[i];
            }
            c.proof = extra;
            assertFalse(compare(c, mode));
            c = generate(13, 3, 1, 9, false);
            c.start = uint256(type(uint32).max) + 1;
            c.indices[0] = c.start;
            assertFalse(compare(c, mode));
        }
    }

    /// @dev Fuzz the 32-bit tree-size domain using bounded synthetic branches.
    function testFuzz_DifferentialDeep(uint32 n, uint32 index, uint64 seed) public {
        uint256 size = n == 0 ? 1 : uint256(n);
        Case memory c = generate(size, uint256(index) % size, 1, seed, true);
        for (uint256 mode; mode < 3; ++mode) {
            assertTrue(compare(c, mode));
        }
    }
}

/// @dev SHA-256 specialization keeps the verifier's hasher constant at each call site.
contract BMTSha256Harness is BMTHarness {
    /// @dev Select the SHA-256 precompile.
    function _hasher() internal pure override returns (address) {
        return address(2);
    }
}

/// @dev Exercise the full BMT suite with SHA-256 and the Rust SHA-256 oracle.
contract LibBMTSha256Test is LibBMTTest {
    /// @dev Select the SHA-256 precompile.
    function _hasher() internal pure override returns (address) {
        return address(2);
    }

    /// @dev Install the SHA-256 harness for memory and calldata verification.
    function setUp() public {
        harness = new BMTSha256Harness();
    }
}
