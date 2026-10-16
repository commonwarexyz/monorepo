// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.15;

import { LibMerkle } from "../src/merkle/LibMerkle.sol";
import { LibMMR } from "../src/merkle/LibMMR.sol";
import {
    MerkleTestCommon,
    Keccak256RootPolicyHarness,
    Sha256RootPolicyHarness,
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
        vm.snapshotGasLastFrame(_group("MMR"), "single-2-memory");
        assertTrue(gasHarness.verifyCalldata(root, 2, 0, a, proof));
        vm.snapshotGasLastFrame(_group("MMR"), "single-2-calldata");
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
        vm.snapshotGasLastFrame(_group("MMR"), "range-2-memory");
        assertTrue(gasHarness.verifyRangeCalldata(root, 2, 0, elements, proof));
        vm.snapshotGasLastFrame(_group("MMR"), "range-2-calldata");
    }

    function testFuzz_CalldataSlices(bytes32 a, bytes32 b) public view {
        checkCalldataSlices(LibMerkle.Family.MMR, a, b);
    }

    function testFuzz_FullRange(uint8 size, bytes32 seed) public view {
        checkFullRange(LibMerkle.Family.MMR, size, seed);
    }

    function testFuzz_SingleLeaf(bytes32 element) public view {
        checkSingleLeaf(LibMerkle.Family.MMR, element);
    }

    function testFuzz_TwoLeaves(bytes32 a, bytes32 b) public view {
        checkTwoLeaves(LibMerkle.Family.MMR, a, b);
    }

    function testFuzz_InvalidBounds(uint256 leaves, uint256 start) public view {
        checkInvalidBounds(LibMerkle.Family.MMR, leaves, start);
    }

    function test_EmptyTree() public view {
        checkEmptyTree(LibMerkle.Family.MMR);
    }

    function test_MemoryExitPaths() public {
        checkMemoryExitPaths(LibMerkle.Family.MMR);
    }

    function testFuzz_MemorySafety(uint8 n, bytes32 seed, bool malformed) public {
        checkMemorySafety(LibMerkle.Family.MMR, n, seed, malformed);
    }

    function testFuzz_DifferentialRange(uint16 n, uint16 s, uint16 len, uint64 seed) public {
        checkDifferentialRange(LibMerkle.Family.MMR, n, s, len, seed);
    }

    function testFuzz_DifferentialIndividual(uint16 n, uint16 s, uint64 seed) public {
        checkDifferentialIndividual(LibMerkle.Family.MMR, n, s, seed);
    }

    function testFuzz_DifferentialDeep(uint8 exponent, uint64 offset, uint64 seed) public {
        checkDifferentialDeep(LibMerkle.Family.MMR, exponent, offset, seed);
    }

    function test_DifferentialPositionBitBoundaries() public {
        checkDifferentialPositionBitBoundaries(LibMerkle.Family.MMR);
    }

    function test_DifferentialMaximumSize() public {
        checkDifferentialMaximumSize(LibMerkle.Family.MMR);
    }

    function testFuzz_DifferentialMalformed(
        uint64 leaves,
        uint64 start,
        bytes32 root,
        bytes32[] memory elements,
        bytes32[] memory proof
    ) public {
        checkDifferentialMalformed(LibMerkle.Family.MMR, leaves, start, root, elements, proof);
    }

    function test_DifferentialSmallRanges() public {
        checkDifferentialSmallRanges(LibMerkle.Family.MMR);
    }

    function test_DifferentialEmpty() public {
        checkDifferentialEmpty(LibMerkle.Family.MMR);
    }

    function test_DifferentialGas() public {
        checkDifferentialGas(LibMerkle.Family.MMR, IMerkleGasHarness(address(gasHarness)));
    }

    function test_DifferentialRootPolicyInactiveBoundaryMatrix() public {
        checkRootPolicyInactiveBoundaryMatrix(LibMerkle.Family.MMR);
    }

    function test_DifferentialRootPolicyRangeMutations() public {
        checkRootPolicyRangeMutations(LibMerkle.Family.MMR);
    }

    function testFuzz_DifferentialRootPolicyRange(
        LibMerkle.Bagging bagging,
        uint8 n,
        uint8 s,
        uint8 len,
        uint8 inactive,
        uint64 seed
    ) public {
        checkRootPolicyRange(LibMerkle.Family.MMR, bagging, n, s, len, inactive, seed);
    }

    function test_DifferentialRootPolicyMaximumSize() public {
        checkRootPolicyMaximumSize(LibMerkle.Family.MMR);
    }

    function testFuzz_DifferentialRootPolicyDeep(LibMerkle.Bagging bagging, uint8 exponent, uint64 offset, uint64 seed)
        public
    {
        checkRootPolicyDeep(LibMerkle.Family.MMR, bagging, exponent, offset, seed);
    }

    function test_DifferentialRootPolicyEmpty() public {
        checkRootPolicyEmpty(LibMerkle.Family.MMR);
    }

    function test_DifferentialRootPolicySparseMatrix() public {
        checkRootPolicySparseMatrix(LibMerkle.Family.MMR);
    }

    function test_DifferentialRootPolicySparseWitnessOrdering() public {
        checkRootPolicySparseWitnessOrdering(LibMerkle.Family.MMR);
    }

    function testFuzz_DifferentialRootPolicySparse(LibMerkle.Bagging bagging, uint8 n, uint64 seed) public {
        checkRootPolicySparse(LibMerkle.Family.MMR, bagging, n, seed);
    }

    function test_DifferentialRootPolicySparseMaximumSize() public {
        checkRootPolicySparseMaximumSize(LibMerkle.Family.MMR);
    }

    function test_DifferentialRootPolicyGas() public {
        checkRootPolicyGas(LibMerkle.Family.MMR);
    }

    function test_DifferentialRootPolicySparseExactUnion() public {
        checkRootPolicySparseExactUnion(LibMerkle.Family.MMR);
    }

    function test_DifferentialRootPolicyInvalidBounds() public {
        checkRootPolicyInvalidBounds(LibMerkle.Family.MMR);
    }

    function test_DifferentialRootPolicyBinding() public {
        checkRootPolicyBinding(LibMerkle.Family.MMR);
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
        harness = new Keccak256RootPolicyHarness();
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
        harness = new Sha256RootPolicyHarness();
    }
}
