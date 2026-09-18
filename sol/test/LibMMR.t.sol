// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.15;

import { LibMerkle } from "../src/merkle/LibMerkle.sol";
import { LibMMR } from "../src/merkle/LibMMR.sol";
import {
    MerkleTestCommon,
    Keccak256CompatibilityHarness,
    Sha256CompatibilityHarness,
    MerkleFamily,
    IMerkleGasHarness,
    HashSelection
} from "./Common.t.sol";

abstract contract MMRHarness is HashSelection {
    function verify(bytes32 root, uint256 leaves, uint256 index, bytes32 element, bytes32[] memory proof)
        external
        view
        returns (bool)
    {
        return LibMMR.verify(root, leaves, index, element, proof, LibMerkle.Bagging.ForwardFold, 0, _hasher());
    }

    function verifyRange(bytes32 root, uint256 leaves, uint256 start, bytes32[] memory elements, bytes32[] memory proof)
        external
        view
        returns (bool)
    {
        return LibMMR.verifyRange(root, leaves, start, elements, proof, LibMerkle.Bagging.ForwardFold, 0, _hasher());
    }

    function verifyCalldata(bytes32 root, uint256 leaves, uint256 index, bytes32 element, bytes32[] calldata proof)
        external
        view
        returns (bool)
    {
        return LibMMR.verifyCalldata(root, leaves, index, element, proof, LibMerkle.Bagging.ForwardFold, 0, _hasher());
    }

    function verifyRangeCalldata(
        bytes32 root,
        uint256 leaves,
        uint256 start,
        bytes32[] calldata elements,
        bytes32[] calldata proof
    ) external view returns (bool) {
        return LibMMR.verifyRangeCalldata(
            root, leaves, start, elements, proof, LibMerkle.Bagging.ForwardFold, 0, _hasher()
        );
    }
}

abstract contract LibMMRTest is MerkleTestCommon {
    MMRHarness internal gasHarness;

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
        checkCalldataSlices(MerkleFamily.MMR, a, b);
    }

    function testFuzz_FullRange(uint8 size, bytes32 seed) public view {
        checkFullRange(MerkleFamily.MMR, size, seed);
    }

    function testFuzz_SingleLeaf(bytes32 element) public view {
        checkSingleLeaf(MerkleFamily.MMR, element);
    }

    function testFuzz_TwoLeaves(bytes32 a, bytes32 b) public view {
        checkTwoLeaves(MerkleFamily.MMR, a, b);
    }

    function testFuzz_InvalidBounds(uint256 leaves, uint256 start) public view {
        checkInvalidBounds(MerkleFamily.MMR, leaves, start);
    }

    function test_EmptyTree() public view {
        checkEmptyTree(MerkleFamily.MMR);
    }

    function test_MemoryExitPaths() public {
        checkMemoryExitPaths(MerkleFamily.MMR);
    }

    function testFuzz_MemorySafety(uint8 n, bytes32 seed, bool malformed) public {
        checkMemorySafety(MerkleFamily.MMR, n, seed, malformed);
    }

    function testFuzz_DifferentialRange(uint16 n, uint16 s, uint16 len, uint64 seed) public {
        checkDifferentialRange(MerkleFamily.MMR, n, s, len, seed);
    }

    function testFuzz_DifferentialIndividual(uint16 n, uint16 s, uint64 seed) public {
        checkDifferentialIndividual(MerkleFamily.MMR, n, s, seed);
    }

    function testFuzz_DifferentialDeep(uint8 exponent, uint64 offset, uint64 seed) public {
        checkDifferentialDeep(MerkleFamily.MMR, exponent, offset, seed);
    }

    function test_DifferentialPositionBitBoundaries() public {
        checkDifferentialPositionBitBoundaries(MerkleFamily.MMR);
    }

    function test_DifferentialMaximumSize() public {
        checkDifferentialMaximumSize(MerkleFamily.MMR);
    }

    function testFuzz_DifferentialMalformed(
        uint64 leaves,
        uint64 start,
        bytes32 root,
        bytes32[] memory elements,
        bytes32[] memory proof
    ) public {
        checkDifferentialMalformed(MerkleFamily.MMR, leaves, start, root, elements, proof);
    }

    function test_DifferentialSmallRanges() public {
        checkDifferentialSmallRanges(MerkleFamily.MMR);
    }

    function test_DifferentialEmpty() public {
        checkDifferentialEmpty(MerkleFamily.MMR);
    }

    function test_DifferentialGas() public {
        checkDifferentialGas(MerkleFamily.MMR, IMerkleGasHarness(address(gasHarness)));
    }

    function test_DifferentialCompatibilityInactiveBoundaryMatrix() public {
        checkCompatibilityInactiveBoundaryMatrix(MerkleFamily.MMR);
    }

    function test_DifferentialCompatibilityRangeMutations() public {
        checkCompatibilityRangeMutations(MerkleFamily.MMR);
    }

    function testFuzz_DifferentialCompatibilityRange(
        bool backward,
        uint8 n,
        uint8 s,
        uint8 len,
        uint8 inactive,
        uint64 seed
    ) public {
        checkCompatibilityRange(MerkleFamily.MMR, backward, n, s, len, inactive, seed);
    }

    function test_DifferentialCompatibilityMaximumSize() public {
        checkCompatibilityMaximumSize(MerkleFamily.MMR);
    }

    function testFuzz_DifferentialCompatibilityDeep(bool backward, uint8 exponent, uint64 offset, uint64 seed) public {
        checkCompatibilityDeep(MerkleFamily.MMR, backward, exponent, offset, seed);
    }

    function test_DifferentialCompatibilityEmpty() public {
        checkCompatibilityEmpty(MerkleFamily.MMR);
    }

    function test_DifferentialCompatibilitySparseMatrix() public {
        checkCompatibilitySparseMatrix(MerkleFamily.MMR);
    }

    function test_DifferentialCompatibilitySparseWitnessOrdering() public {
        checkCompatibilitySparseWitnessOrdering(MerkleFamily.MMR);
    }

    function testFuzz_DifferentialCompatibilitySparse(bool backward, uint8 n, uint64 seed) public {
        checkCompatibilitySparse(MerkleFamily.MMR, backward, n, seed);
    }

    function test_DifferentialCompatibilitySparseMaximumSize() public {
        checkCompatibilitySparseMaximumSize(MerkleFamily.MMR);
    }

    function test_DifferentialRootPolicyGas() public {
        checkRootPolicyGas(MerkleFamily.MMR);
    }

    function test_DifferentialCompatibilitySparseExactUnion() public {
        checkCompatibilitySparseExactUnion(MerkleFamily.MMR);
    }

    function test_DifferentialCompatibilityInvalidBounds() public {
        checkCompatibilityInvalidBounds(MerkleFamily.MMR);
    }

    function test_DifferentialCompatibilityRootPolicyBinding() public {
        checkCompatibilityRootPolicyBinding(MerkleFamily.MMR);
    }
}

contract MMRKeccak256Harness is MMRHarness {
    function _hasher() internal pure override returns (address) {
        return address(0);
    }
}

contract LibMMRKeccak256Test is LibMMRTest {
    function _hasher() internal pure override returns (address) {
        return address(0);
    }

    function setUp() public {
        gasHarness = new MMRKeccak256Harness();
        harness = new Keccak256CompatibilityHarness();
    }
}

contract MMRSha256Harness is MMRHarness {
    function _hasher() internal pure override returns (address) {
        return address(2);
    }
}

contract LibMMRSha256Test is LibMMRTest {
    function _hasher() internal pure override returns (address) {
        return address(2);
    }

    function setUp() public {
        gasHarness = new MMRSha256Harness();
        harness = new Sha256CompatibilityHarness();
    }
}
