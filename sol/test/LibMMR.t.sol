// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.15;

import { LibMMR } from "../src/merkle/LibMMR.sol";
import { MerkleTestCommon, CompatibilityHarness, IMerkleGasHarness, HashSelection } from "./Common.t.sol";

contract MMRHarness is HashSelection {
    function verify(bytes32 root, uint256 leaves, uint256 index, bytes32 element, bytes32[] memory proof)
        external
        view
        returns (bool)
    {
        return LibMMR.verify(root, leaves, index, element, proof, _hasher());
    }

    function verifyRange(bytes32 root, uint256 leaves, uint256 start, bytes32[] memory elements, bytes32[] memory proof)
        external
        view
        returns (bool)
    {
        return LibMMR.verifyRange(root, leaves, start, elements, proof, _hasher());
    }

    function verifyCalldata(bytes32 root, uint256 leaves, uint256 index, bytes32 element, bytes32[] calldata proof)
        external
        view
        returns (bool)
    {
        return LibMMR.verifyCalldata(root, leaves, index, element, proof, _hasher());
    }

    function verifyRangeCalldata(
        bytes32 root,
        uint256 leaves,
        uint256 start,
        bytes32[] calldata elements,
        bytes32[] calldata proof
    ) external view returns (bool) {
        return LibMMR.verifyRangeCalldata(root, leaves, start, elements, proof, _hasher());
    }
}

contract MMRCompatibilityHarness is CompatibilityHarness { }

contract LibMMRTest is MerkleTestCommon {
    MMRHarness internal gasHarness = new MMRHarness();

    function setUp() public virtual {
        harness = new MMRCompatibilityHarness();
    }

    function testGas_IndividualTwoLeaves() public {
        bytes32 a = bytes32(uint256(11));
        bytes32 b = bytes32(uint256(22));
        bytes32 left = _hash(abi.encodePacked(uint64(0), a));
        bytes32 right = _hash(abi.encodePacked(uint64(1), b));
        bytes32 root = _hash(abi.encodePacked(uint64(2), _hash(abi.encodePacked(uint64(2), left, right))));
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = right;
        assertTrue(gasHarness.verify(root, 2, 0, a, proof));
        vm.snapshotGasLastFrame(_group("MMR"), "individual-2");
        assertTrue(gasHarness.verifyCalldata(root, 2, 0, a, proof));
        vm.snapshotGasLastFrame(_group("MMR"), "individual-2-calldata");
    }

    function testGas_RangeTwoLeaves() public {
        bytes32[] memory elements = new bytes32[](2);
        elements[0] = bytes32(uint256(11));
        elements[1] = bytes32(uint256(22));
        bytes32 left = _hash(abi.encodePacked(uint64(0), elements[0]));
        bytes32 right = _hash(abi.encodePacked(uint64(1), elements[1]));
        bytes32 root = _hash(abi.encodePacked(uint64(2), _hash(abi.encodePacked(uint64(2), left, right))));
        bytes32[] memory proof = new bytes32[](0);
        assertTrue(gasHarness.verifyRange(root, 2, 0, elements, proof));
        vm.snapshotGasLastFrame(_group("MMR"), "range-2");
        assertTrue(gasHarness.verifyRangeCalldata(root, 2, 0, elements, proof));
        vm.snapshotGasLastFrame(_group("MMR"), "range-2-calldata");
    }

    function testFuzz_CalldataSlices(bytes32 a, bytes32 b) public view {
        checkCalldataSlices(false, a, b);
    }

    function testFuzz_FullRange(uint8 size, bytes32 seed) public view {
        checkFullRange(false, size, seed);
    }

    function testFuzz_SingleLeaf(bytes32 element) public view {
        checkSingleLeaf(false, element);
    }

    function testFuzz_TwoLeaves(bytes32 a, bytes32 b) public view {
        checkTwoLeaves(false, a, b);
    }

    function testFuzz_InvalidBounds(uint256 leaves, uint256 start) public view {
        checkInvalidBounds(false, leaves, start);
    }

    function test_EmptyTree() public view {
        checkEmptyTree(false);
    }

    function test_MemoryExitPaths() public {
        checkMemoryExitPaths(false);
    }

    function testFuzz_MemorySafety(uint8 n, bytes32 seed, bool malformed) public {
        checkMemorySafety(false, n, seed, malformed);
    }

    function testFuzz_DifferentialRange(uint16 n, uint16 s, uint16 len, uint64 seed) public {
        checkDifferentialRange(false, n, s, len, seed);
    }

    function testFuzz_DifferentialIndividual(uint16 n, uint16 s, uint64 seed) public {
        checkDifferentialIndividual(false, n, s, seed);
    }

    function testFuzz_DifferentialDeep(uint8 exponent, uint64 offset, uint64 seed) public {
        checkDifferentialDeep(false, exponent, offset, seed);
    }

    function test_DifferentialPositionBitBoundaries() public {
        checkDifferentialPositionBitBoundaries(false);
    }

    function test_DifferentialMaximumSize() public {
        checkDifferentialMaximumSize(false);
    }

    function testFuzz_DifferentialMalformed(
        uint64 leaves,
        uint64 start,
        bytes32 root,
        bytes32[] memory elements,
        bytes32[] memory proof
    ) public {
        checkDifferentialMalformed(false, leaves, start, root, elements, proof);
    }

    function test_DifferentialSmallRanges() public {
        checkDifferentialSmallRanges(false);
    }

    function test_DifferentialEmpty() public {
        checkDifferentialEmpty(false);
    }

    function test_DifferentialGas() public {
        checkDifferentialGas(false, IMerkleGasHarness(address(gasHarness)));
    }

    function test_DifferentialCompatibilityInactiveBoundaryMatrix() public {
        checkCompatibilityInactiveBoundaryMatrix(false);
    }

    function test_DifferentialCompatibilityRangeMutations() public {
        checkCompatibilityRangeMutations(false);
    }

    function testFuzz_DifferentialCompatibilityRange(
        bool backward,
        uint8 n,
        uint8 s,
        uint8 len,
        uint8 inactive,
        uint64 seed
    ) public {
        checkCompatibilityRange(false, backward, n, s, len, inactive, seed);
    }

    function test_DifferentialCompatibilityMaximumSize() public {
        checkCompatibilityMaximumSize(false);
    }

    function testFuzz_DifferentialCompatibilityDeep(bool backward, uint8 exponent, uint64 offset, uint64 seed) public {
        checkCompatibilityDeep(false, backward, exponent, offset, seed);
    }

    function test_DifferentialCompatibilityEmpty() public {
        checkCompatibilityEmpty(false);
    }

    function test_DifferentialCompatibilitySparseMatrix() public {
        checkCompatibilitySparseMatrix(false);
    }

    function test_DifferentialCompatibilitySparseWitnessOrdering() public {
        checkCompatibilitySparseWitnessOrdering(false);
    }

    function testFuzz_DifferentialCompatibilitySparse(bool backward, uint8 n, uint64 seed) public {
        checkCompatibilitySparse(false, backward, n, seed);
    }

    function test_DifferentialCompatibilitySparseMaximumSize() public {
        checkCompatibilitySparseMaximumSize(false);
    }

    function test_DifferentialCompatibilityGas() public {
        checkCompatibilityGas(false);
    }

    function test_DifferentialCompatibilitySparseExactUnion() public {
        checkCompatibilitySparseExactUnion(false);
    }

    function test_DifferentialCompatibilityInvalidBounds() public {
        checkCompatibilityInvalidBounds(false);
    }

    function test_DifferentialCompatibilityRootPolicyBinding() public {
        checkCompatibilityRootPolicyBinding(false);
    }
}

/// @dev SHA-256 specialization keeps the verifier's hasher constant at each call site.
contract MMRSha256Harness is MMRHarness {
    /// @dev Select the SHA-256 precompile.
    function _hasher() internal pure override returns (address) {
        return address(2);
    }
}

contract MMRSha256CompatibilityHarness is CompatibilityHarness {
    /// @dev Select the SHA-256 precompile.
    function _hasher() internal pure override returns (address) {
        return address(2);
    }
}

/// @dev Run the complete family suite against Commonware SHA-256 roots.
contract LibMMRSha256Test is LibMMRTest {
    /// @dev Select the SHA-256 precompile.
    function _hasher() internal pure override returns (address) {
        return address(2);
    }

    /// @dev Install harnesses with the same hash algorithm as the reference builder.
    function setUp() public override {
        gasHarness = new MMRSha256Harness();
        harness = new MMRSha256CompatibilityHarness();
    }
}
