// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.15;

import { LibMerkle } from "../src/merkle/LibMerkle.sol";
import { LibMMB } from "../src/merkle/LibMMB.sol";
import {
    MerkleTestCommon,
    Keccak256RootPolicyHarness,
    Sha256RootPolicyHarness,
    IMerkleGasHarness,
    HashSelection
} from "./Common.t.sol";

abstract contract MMBHarness is HashSelection {
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

abstract contract LibMMBTest is MerkleTestCommon {
    MMBHarness internal gasHarness;

    function testGas_IndividualTwoLeaves() public {
        bytes32 a = bytes32(uint256(11));
        bytes32 b = bytes32(uint256(22));
        bytes32 left = _hash(abi.encodePacked(uint64(0), a));
        bytes32 right = _hash(abi.encodePacked(uint64(1), b));
        bytes32 root = _hash(abi.encodePacked(uint64(2), _hash(abi.encodePacked(uint64(2), left, right))));
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = right;
        assertTrue(gasHarness.verify(root, 2, 0, a, proof));
        vm.snapshotGasLastFrame(_group("MMB"), "single-2-memory");
        assertTrue(gasHarness.verifyCalldata(root, 2, 0, a, proof));
        vm.snapshotGasLastFrame(_group("MMB"), "single-2-calldata");
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
        vm.snapshotGasLastFrame(_group("MMB"), "range-2-memory");
        assertTrue(gasHarness.verifyRangeCalldata(root, 2, 0, elements, proof));
        vm.snapshotGasLastFrame(_group("MMB"), "range-2-calldata");
    }

    function testFuzz_CalldataSlices(bytes32 a, bytes32 b) public view {
        checkCalldataSlices(LibMerkle.Family.MMB, a, b);
    }

    function testFuzz_FullRange(uint8 size, bytes32 seed) public view {
        checkFullRange(LibMerkle.Family.MMB, size, seed);
    }

    function testFuzz_SingleLeaf(bytes32 element) public view {
        checkSingleLeaf(LibMerkle.Family.MMB, element);
    }

    function testFuzz_TwoLeaves(bytes32 a, bytes32 b) public view {
        checkTwoLeaves(LibMerkle.Family.MMB, a, b);
    }

    function testFuzz_InvalidBounds(uint256 leaves, uint256 start) public view {
        checkInvalidBounds(LibMerkle.Family.MMB, leaves, start);
    }

    function test_EmptyTree() public view {
        checkEmptyTree(LibMerkle.Family.MMB);
    }

    function test_MemoryExitPaths() public {
        checkMemoryExitPaths(LibMerkle.Family.MMB);
    }

    function testFuzz_MemorySafety(uint8 n, bytes32 seed, bool malformed) public {
        checkMemorySafety(LibMerkle.Family.MMB, n, seed, malformed);
    }

    function testFuzz_DifferentialRange(uint16 n, uint16 s, uint16 len, uint64 seed) public {
        checkDifferentialRange(LibMerkle.Family.MMB, n, s, len, seed);
    }

    function testFuzz_DifferentialIndividual(uint16 n, uint16 s, uint64 seed) public {
        checkDifferentialIndividual(LibMerkle.Family.MMB, n, s, seed);
    }

    function testFuzz_DifferentialDeep(uint8 exponent, uint64 offset, uint64 seed) public {
        checkDifferentialDeep(LibMerkle.Family.MMB, exponent, offset, seed);
    }

    function test_DifferentialPositionBitBoundaries() public {
        checkDifferentialPositionBitBoundaries(LibMerkle.Family.MMB);
    }

    function test_DifferentialMaximumSize() public {
        checkDifferentialMaximumSize(LibMerkle.Family.MMB);
    }

    function testFuzz_DifferentialMalformed(
        uint64 leaves,
        uint64 start,
        bytes32 root,
        bytes32[] memory elements,
        bytes32[] memory proof
    ) public {
        checkDifferentialMalformed(LibMerkle.Family.MMB, leaves, start, root, elements, proof);
    }

    function test_DifferentialSmallRanges() public {
        checkDifferentialSmallRanges(LibMerkle.Family.MMB);
    }

    function test_DifferentialEmpty() public {
        checkDifferentialEmpty(LibMerkle.Family.MMB);
    }

    function test_DifferentialGas() public {
        checkDifferentialGas(LibMerkle.Family.MMB, IMerkleGasHarness(address(gasHarness)));
    }

    function test_DifferentialRootPolicyInactiveBoundaryMatrix() public {
        checkRootPolicyInactiveBoundaryMatrix(LibMerkle.Family.MMB);
    }

    function test_DifferentialRootPolicyRangeMutations() public {
        checkRootPolicyRangeMutations(LibMerkle.Family.MMB);
    }

    function testFuzz_DifferentialRootPolicyRange(
        LibMerkle.Bagging bagging,
        uint8 n,
        uint8 s,
        uint8 len,
        uint8 inactive,
        uint64 seed
    ) public {
        checkRootPolicyRange(LibMerkle.Family.MMB, bagging, n, s, len, inactive, seed);
    }

    function test_DifferentialRootPolicyMaximumSize() public {
        checkRootPolicyMaximumSize(LibMerkle.Family.MMB);
    }

    function testFuzz_DifferentialRootPolicyDeep(LibMerkle.Bagging bagging, uint8 exponent, uint64 offset, uint64 seed)
        public
    {
        checkRootPolicyDeep(LibMerkle.Family.MMB, bagging, exponent, offset, seed);
    }

    function test_DifferentialRootPolicyEmpty() public {
        checkRootPolicyEmpty(LibMerkle.Family.MMB);
    }

    function test_DifferentialRootPolicySparseMatrix() public {
        checkRootPolicySparseMatrix(LibMerkle.Family.MMB);
    }

    function test_DifferentialRootPolicySparseWitnessOrdering() public {
        checkRootPolicySparseWitnessOrdering(LibMerkle.Family.MMB);
    }

    function testFuzz_DifferentialRootPolicySparse(LibMerkle.Bagging bagging, uint8 n, uint64 seed) public {
        checkRootPolicySparse(LibMerkle.Family.MMB, bagging, n, seed);
    }

    function test_DifferentialRootPolicySparseMaximumSize() public {
        checkRootPolicySparseMaximumSize(LibMerkle.Family.MMB);
    }

    function test_DifferentialRootPolicyGas() public {
        checkRootPolicyGas(LibMerkle.Family.MMB);
    }

    function test_DifferentialRootPolicySparseExactUnion() public {
        checkRootPolicySparseExactUnion(LibMerkle.Family.MMB);
    }

    function test_DifferentialRootPolicyInvalidBounds() public {
        checkRootPolicyInvalidBounds(LibMerkle.Family.MMB);
    }

    function test_DifferentialRootPolicyBinding() public {
        checkRootPolicyBinding(LibMerkle.Family.MMB);
    }
}

contract MMBKeccak256Harness is MMBHarness {
    function _hasher() internal pure override returns (address) {
        return address(0);
    }
}

contract LibMMBKeccak256Test is LibMMBTest {
    function _hasher() internal pure override returns (address) {
        return address(0);
    }

    function setUp() public {
        gasHarness = new MMBKeccak256Harness();
        harness = new Keccak256RootPolicyHarness();
    }
}

contract MMBSha256Harness is MMBHarness {
    function _hasher() internal pure override returns (address) {
        return address(2);
    }
}

contract LibMMBSha256Test is LibMMBTest {
    function _hasher() internal pure override returns (address) {
        return address(2);
    }

    function setUp() public {
        gasHarness = new MMBSha256Harness();
        harness = new Sha256RootPolicyHarness();
    }
}
