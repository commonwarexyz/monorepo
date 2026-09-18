// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.15;

import { LibMerkle } from "../src/merkle/LibMerkle.sol";
import { LibMMB } from "../src/merkle/LibMMB.sol";
import { MerkleTestCommon, CompatibilityHarness, IMerkleGasHarness, HashSelection } from "./Common.t.sol";

contract MMBHarness is HashSelection {
    function verify(bytes32 root, uint256 leaves, uint256 index, bytes32 element, bytes32[] memory proof)
        external
        view
        returns (bool)
    {
        return LibMMB.verify(root, leaves, index, element, proof, LibMerkle.Bagging.ForwardFold, 0, _hasher());
    }

    function verifyRange(bytes32 root, uint256 leaves, uint256 start, bytes32[] memory elements, bytes32[] memory proof)
        external
        view
        returns (bool)
    {
        return LibMMB.verifyRange(root, leaves, start, elements, proof, LibMerkle.Bagging.ForwardFold, 0, _hasher());
    }

    function verifyCalldata(bytes32 root, uint256 leaves, uint256 index, bytes32 element, bytes32[] calldata proof)
        external
        view
        returns (bool)
    {
        return LibMMB.verifyCalldata(root, leaves, index, element, proof, LibMerkle.Bagging.ForwardFold, 0, _hasher());
    }

    function verifyRangeCalldata(
        bytes32 root,
        uint256 leaves,
        uint256 start,
        bytes32[] calldata elements,
        bytes32[] calldata proof
    ) external view returns (bool) {
        return LibMMB.verifyRangeCalldata(
            root, leaves, start, elements, proof, LibMerkle.Bagging.ForwardFold, 0, _hasher()
        );
    }
}

contract MMBCompatibilityHarness is CompatibilityHarness { }

contract LibMMBTest is MerkleTestCommon {
    MMBHarness internal gasHarness = new MMBHarness();

    function setUp() public virtual {
        harness = new MMBCompatibilityHarness();
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
        vm.snapshotGasLastFrame(_group("MMB"), "individual-2");
        assertTrue(gasHarness.verifyCalldata(root, 2, 0, a, proof));
        vm.snapshotGasLastFrame(_group("MMB"), "individual-2-calldata");
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
        vm.snapshotGasLastFrame(_group("MMB"), "range-2");
        assertTrue(gasHarness.verifyRangeCalldata(root, 2, 0, elements, proof));
        vm.snapshotGasLastFrame(_group("MMB"), "range-2-calldata");
    }

    function testFuzz_CalldataSlices(bytes32 a, bytes32 b) public view {
        checkCalldataSlices(true, a, b);
    }

    function testFuzz_FullRange(uint8 size, bytes32 seed) public view {
        checkFullRange(true, size, seed);
    }

    function testFuzz_SingleLeaf(bytes32 element) public view {
        checkSingleLeaf(true, element);
    }

    function testFuzz_TwoLeaves(bytes32 a, bytes32 b) public view {
        checkTwoLeaves(true, a, b);
    }

    function testFuzz_InvalidBounds(uint256 leaves, uint256 start) public view {
        checkInvalidBounds(true, leaves, start);
    }

    function test_EmptyTree() public view {
        checkEmptyTree(true);
    }

    function test_MemoryExitPaths() public {
        checkMemoryExitPaths(true);
    }

    function testFuzz_MemorySafety(uint8 n, bytes32 seed, bool malformed) public {
        checkMemorySafety(true, n, seed, malformed);
    }

    function testFuzz_DifferentialRange(uint16 n, uint16 s, uint16 len, uint64 seed) public {
        checkDifferentialRange(true, n, s, len, seed);
    }

    function testFuzz_DifferentialIndividual(uint16 n, uint16 s, uint64 seed) public {
        checkDifferentialIndividual(true, n, s, seed);
    }

    function testFuzz_DifferentialDeep(uint8 exponent, uint64 offset, uint64 seed) public {
        checkDifferentialDeep(true, exponent, offset, seed);
    }

    function test_DifferentialPositionBitBoundaries() public {
        checkDifferentialPositionBitBoundaries(true);
    }

    function test_DifferentialMaximumSize() public {
        checkDifferentialMaximumSize(true);
    }

    function testFuzz_DifferentialMalformed(
        uint64 leaves,
        uint64 start,
        bytes32 root,
        bytes32[] memory elements,
        bytes32[] memory proof
    ) public {
        checkDifferentialMalformed(true, leaves, start, root, elements, proof);
    }

    function test_DifferentialSmallRanges() public {
        checkDifferentialSmallRanges(true);
    }

    function test_DifferentialEmpty() public {
        checkDifferentialEmpty(true);
    }

    function test_DifferentialGas() public {
        checkDifferentialGas(true, IMerkleGasHarness(address(gasHarness)));
    }

    function test_DifferentialCompatibilityInactiveBoundaryMatrix() public {
        checkCompatibilityInactiveBoundaryMatrix(true);
    }

    function test_DifferentialCompatibilityRangeMutations() public {
        checkCompatibilityRangeMutations(true);
    }

    function testFuzz_DifferentialCompatibilityRange(
        bool backward,
        uint8 n,
        uint8 s,
        uint8 len,
        uint8 inactive,
        uint64 seed
    ) public {
        checkCompatibilityRange(true, backward, n, s, len, inactive, seed);
    }

    function test_DifferentialCompatibilityMaximumSize() public {
        checkCompatibilityMaximumSize(true);
    }

    function testFuzz_DifferentialCompatibilityDeep(bool backward, uint8 exponent, uint64 offset, uint64 seed) public {
        checkCompatibilityDeep(true, backward, exponent, offset, seed);
    }

    function test_DifferentialCompatibilityEmpty() public {
        checkCompatibilityEmpty(true);
    }

    function test_DifferentialCompatibilitySparseMatrix() public {
        checkCompatibilitySparseMatrix(true);
    }

    function test_DifferentialCompatibilitySparseWitnessOrdering() public {
        checkCompatibilitySparseWitnessOrdering(true);
    }

    function testFuzz_DifferentialCompatibilitySparse(bool backward, uint8 n, uint64 seed) public {
        checkCompatibilitySparse(true, backward, n, seed);
    }

    function test_DifferentialCompatibilitySparseMaximumSize() public {
        checkCompatibilitySparseMaximumSize(true);
    }

    function test_DifferentialRootPolicyGas() public {
        checkRootPolicyGas(true);
    }

    function test_DifferentialCompatibilitySparseExactUnion() public {
        checkCompatibilitySparseExactUnion(true);
    }

    function test_DifferentialCompatibilityInvalidBounds() public {
        checkCompatibilityInvalidBounds(true);
    }

    function test_DifferentialCompatibilityRootPolicyBinding() public {
        checkCompatibilityRootPolicyBinding(true);
    }
}

/// @dev SHA-256 specialization keeps the verifier's hasher constant at each call site.
contract MMBSha256Harness is MMBHarness {
    /// @dev Select the SHA-256 precompile.
    function _hasher() internal pure override returns (address) {
        return address(2);
    }
}

contract MMBSha256CompatibilityHarness is CompatibilityHarness {
    /// @dev Select the SHA-256 precompile.
    function _hasher() internal pure override returns (address) {
        return address(2);
    }
}

/// @dev Run the complete family suite against Commonware SHA-256 roots.
contract LibMMBSha256Test is LibMMBTest {
    /// @dev Select the SHA-256 precompile.
    function _hasher() internal pure override returns (address) {
        return address(2);
    }

    /// @dev Install harnesses with the same hash algorithm as the reference builder.
    function setUp() public override {
        gasHarness = new MMBSha256Harness();
        harness = new MMBSha256CompatibilityHarness();
    }
}
