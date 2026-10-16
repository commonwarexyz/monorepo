// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.15;

import { RawSha256Hasher, ProofKind } from "./Common.t.sol";
import { LibMerkle } from "../src/merkle/LibMerkle.sol";
import { LibQMDBCommon } from "../src/qmdb/LibQMDBCommon.sol";
import { LibQMDBBatchTest, BatchCase, PlainFacade } from "./LibQMDBBatch.t.sol";
import { LibQMDBCurrentTest, QMDBCase } from "./LibQMDBCurrent.t.sol";
import { LibQMDBAnyMMB } from "../src/qmdb/LibQMDBAnyMMB.sol";
import { LibQMDBAnyMMR } from "../src/qmdb/LibQMDBAnyMMR.sol";
import { LibQMDBKeylessMMB } from "../src/qmdb/LibQMDBKeylessMMB.sol";
import { LibQMDBKeylessMMR } from "../src/qmdb/LibQMDBKeylessMMR.sol";
import { LibQMDBImmutableMMB } from "../src/qmdb/LibQMDBImmutableMMB.sol";
import { LibQMDBImmutableMMR } from "../src/qmdb/LibQMDBImmutableMMR.sol";
import { LibQMDBCurrent } from "../src/qmdb/LibQMDBCurrent.sol";
import { LibQMDBCurrentMMB } from "../src/qmdb/LibQMDBCurrentMMB.sol";
import { LibQMDBCurrentMMR } from "../src/qmdb/LibQMDBCurrentMMR.sol";

/// @dev Hash all other preimages correctly so failures can be isolated by hashing stage.
contract QMDBLengthFaultHasher {
    uint256 internal immutable trigger;
    uint256 internal immutable responseLength;
    bool internal immutable fails;

    /// @dev Configure the preimage length that reverts or returns malformed raw data.
    constructor(uint256 inputLength, uint256 outputLength, bool reverts) {
        trigger = inputLength;
        responseLength = outputLength;
        fails = reverts;
    }

    /// @dev Successful calls return exactly the SHA-256 digest without ABI framing.
    fallback(bytes calldata input) external returns (bytes memory) {
        if (input.length == trigger) {
            require(!fails);
            return new bytes(responseLength);
        }
        return abi.encodePacked(sha256(input));
    }
}

/// @dev Reuse append-history builders and batch caller-memory checks with a raw contract target.
abstract contract LibQMDBHashTest is LibQMDBBatchTest {
    LibQMDBBatchTest internal precompile;
    LibQMDBCurrentTest internal currentBuilder;

    /// @dev Select a non-precompile address whose code is installed before each test.
    function _hasher() internal pure override returns (address) {
        return address(0x514d4442);
    }

    /// @dev Keep independent SHA-256 reference builders and the raw target available to every test.
    function setUp() public {
        vm.etch(_hasher(), address(new RawSha256Hasher()).code);
        precompile = LibQMDBBatchTest(
            deployCode(
                _family() == LibMerkle.Family.MMB
                    ? "LibQMDBBatch.t.sol:LibQMDBBatchMMBSha256Test"
                    : "LibQMDBBatch.t.sol:LibQMDBBatchMMRSha256Test"
            )
        );
        currentBuilder = LibQMDBCurrentTest(
            deployCode(
                _family() == LibMerkle.Family.MMB
                    ? "LibQMDBCurrent.t.sol:LibQMDBCurrentMMBSha256Test"
                    : "LibQMDBCurrent.t.sol:LibQMDBCurrentMMRSha256Test"
            )
        );
    }

    /// @dev Expose the Any singleton facade with an explicit raw hash target.
    function singleAny(bytes32 root, bytes memory operation, LibQMDBCommon.Proof calldata proof, address hasher)
        external
        view
        returns (bool)
    {
        return _family() == LibMerkle.Family.MMB
            ? LibQMDBAnyMMB.verify(root, operation, proof, hasher)
            : LibQMDBAnyMMR.verify(root, operation, proof, hasher);
    }

    /// @dev Expose the Keyless singleton facade with the same wire-shaped proof fields.
    function singleKeyless(bytes32 root, bytes memory operation, LibQMDBCommon.Proof calldata proof, address hasher)
        external
        view
        returns (bool)
    {
        return _family() == LibMerkle.Family.MMB
            ? LibQMDBKeylessMMB.verify(root, operation, proof, hasher)
            : LibQMDBKeylessMMR.verify(root, operation, proof, hasher);
    }

    /// @dev Expose the Immutable singleton facade with the same wire-shaped proof fields.
    function singleImmutable(bytes32 root, bytes memory operation, LibQMDBCommon.Proof calldata proof, address hasher)
        external
        view
        returns (bool)
    {
        return _family() == LibMerkle.Family.MMB
            ? LibQMDBImmutableMMB.verify(root, operation, proof, hasher)
            : LibQMDBImmutableMMR.verify(root, operation, proof, hasher);
    }

    function singleCurrentMembership(QMDBCase calldata c, address hasher) external view returns (bool) {
        return _family() == LibMerkle.Family.MMB
            ? LibQMDBCurrentMMB.verify(c.root, c.operation, c.proof, c.chunkBytes, hasher)
            : LibQMDBCurrentMMR.verify(c.root, c.operation, c.proof, c.chunkBytes, hasher);
    }

    /// @dev Query an interior key in the fixed-width exclusion fixtures.
    function singleCurrentExclusion(QMDBCase calldata c, address hasher) external view returns (bool) {
        LibQMDBCurrent.Schema memory schema = LibQMDBCurrent.Schema(LibQMDBCurrent.Encoding.Fixed, 32, 0);
        return _family() == LibMerkle.Family.MMB
            ? LibQMDBCurrentMMB.verifyExclusion(
                c.root, abi.encodePacked(bytes32(uint256(15))), c.operation, c.proof, schema, c.chunkBytes, hasher
            )
            : LibQMDBCurrentMMR.verifyExclusion(
                c.root, abi.encodePacked(bytes32(uint256(15))), c.operation, c.proof, schema, c.chunkBytes, hasher
            );
    }

    /// @dev Singleton facades use identical ABI tuple fields, allowing one shared fixture.
    function singletonCall(BatchCase memory c, PlainFacade facade, address hasher)
        internal
        pure
        returns (bytes memory)
    {
        bytes4[3] memory selectors =
            [this.singleAny.selector, this.singleKeyless.selector, this.singleImmutable.selector];
        LibQMDBCommon.Proof memory proof = LibQMDBCommon.Proof(c.range.leaves, c.range.start, 0, c.range.digests);
        return abi.encodeWithSelector(selectors[uint256(facade)], c.root, c.operations[0], proof, hasher);
    }

    /// @dev Require the encoded entrypoint to succeed and return true.
    function accepted(bytes memory input) internal view {
        (bool success, bytes memory output) = address(this).staticcall(input);
        assertTrue(success, "verification reverted");
        assertTrue(abi.decode(output, (bool)), "valid proof rejected");
    }

    /// @dev Every plain singleton facade accepts exactly the same SHA-256 commitment.
    function test_RawSingletonsMatchPrecompile() public view {
        BatchCase memory c = operationsCase(13, sequence(3, 1), ProofKind.Range);
        for (uint256 facadeIndex; facadeIndex <= uint256(PlainFacade.Immutable); ++facadeIndex) {
            PlainFacade facade = PlainFacade(facadeIndex);
            accepted(singletonCall(c, facade, address(2)));
            accepted(singletonCall(c, facade, _hasher()));
        }
    }

    /// @dev Range and genuinely separated sparse queries share the precompile verdict and memory invariants.
    function test_RawBatchesMatchPrecompile() public view {
        uint256[] memory locations = sequence(2, 3);
        for (uint256 proofIndex; proofIndex < 2; ++proofIndex) {
            ProofKind proofKind = proofIndex == 0 ? ProofKind.Range : ProofKind.Multi;
            if (proofKind == ProofKind.Multi) {
                locations[1] = 8;
                locations[2] = 12;
            }
            BatchCase memory c = operationsCase(13, locations, proofKind);
            assertTrue(precompile.checked(c));
            assertTrue(this.checked(c));
            c.operations[0] = bytes.concat(c.operations[0], hex"ff");
            assertFalse(precompile.checked(c));
            assertFalse(this.checked(c));
        }
        for (uint256 proofIndex; proofIndex < 2; ++proofIndex) {
            ProofKind proofKind = proofIndex == 0 ? ProofKind.Range : ProofKind.Multi;
            BatchCase memory c = currentCase32(513, 254, 5, proofKind, false);
            assertTrue(precompile.checked(c));
            assertTrue(this.checked(c));
            c.root ^= bytes32(uint256(1));
            assertFalse(precompile.checked(c));
            assertFalse(this.checked(c));
        }
    }

    /// @dev Membership and exclusion both authenticate through a graft and a partial final chunk.
    function test_RawCurrentSingletonAndExclusionMatchPrecompile() public view {
        bytes memory operation = abi.encodePacked(bytes1(0xd2), bytes32(uint256(10)), bytes32(uint256(20)));
        QMDBCase memory c = currentBuilder.build(33, 0, operation, true, 2);
        assertTrue(this.singleCurrentMembership(c, address(2)));
        assertTrue(this.singleCurrentMembership(c, _hasher()));
        assertTrue(this.singleCurrentExclusion(c, address(2)));
        assertTrue(this.singleCurrentExclusion(c, _hasher()));
        c.root ^= bytes32(uint256(1));
        assertFalse(this.singleCurrentMembership(c, address(2)));
        assertFalse(this.singleCurrentMembership(c, _hasher()));
        assertFalse(this.singleCurrentExclusion(c, address(2)));
        assertFalse(this.singleCurrentExclusion(c, _hasher()));
    }

    /// @dev A reverting call and zero, short, or oversized output must all surface HashFailed.
    function assertStageFailures(bytes memory input, uint256 length) internal {
        uint256[5] memory lengths = [uint256(0), 0, 31, 33, 64];
        for (uint256 mode; mode < lengths.length; ++mode) {
            vm.etch(_hasher(), address(new QMDBLengthFaultHasher(length, lengths[mode], mode == 0)).code);
            (bool success, bytes memory output) = address(this).staticcall(input);
            assertFalse(success, "hash failure did not revert");
            assertEq(output, abi.encodeWithSelector(LibMerkle.HashFailed.selector), "wrong hash failure");
        }
        vm.etch(_hasher(), address(new RawSha256Hasher()).code);
        accepted(input);
    }

    /// @dev Leaf, positioned parent, peak fold, and leaf-count root calls all enforce raw response framing.
    function test_RawPlainHashFailuresByStage() public {
        BatchCase memory c = operationsCase(13, sequence(0, 1), ProofKind.Range);
        uint256[4] memory stages = [uint256(12), 72, 64, 40];
        for (uint256 facadeIndex; facadeIndex <= uint256(PlainFacade.Immutable); ++facadeIndex) {
            PlainFacade facade = PlainFacade(facadeIndex);
            bytes memory input = singletonCall(c, facade, _hasher());
            for (uint256 stage; stage < stages.length; ++stage) {
                assertStageFailures(input, stages[stage]);
            }
        }
        for (uint256 proofIndex; proofIndex < 2; ++proofIndex) {
            ProofKind proofKind = proofIndex == 0 ? ProofKind.Range : ProofKind.Multi;
            c = operationsCase(13, sequence(0, 2), proofKind);
            bytes memory input = abi.encodeCall(this.checked, (c));
            for (uint256 stage; stage < stages.length; ++stage) {
                assertStageFailures(input, stages[stage]);
            }
        }
    }

    /// @dev Distinct preimage sizes isolate leaf, parent, bitmap graft, Merkle root, and Current root failures.
    function test_RawCurrentHashFailuresByStage() public {
        QMDBCase memory c = currentBuilder.build(33, 0, hex"010203", true, 2);
        bytes memory input = abi.encodeCall(this.singleCurrentMembership, (c, _hasher()));
        uint256[5] memory stages = [uint256(11), 72, 34, 40, 104 + (c.proof.pending == 0 ? 0 : 32)];
        for (uint256 stage; stage < stages.length; ++stage) {
            assertStageFailures(input, stages[stage]);
        }
        c.operation = abi.encodePacked(bytes1(0xd2), bytes32(uint256(10)), bytes32(uint256(20)));
        c = currentBuilder.build(33, 0, c.operation, true, 2);
        assertStageFailures(abi.encodeCall(this.singleCurrentExclusion, (c, _hasher())), 34);
        for (uint256 proofIndex; proofIndex < 2; ++proofIndex) {
            ProofKind proofKind = proofIndex == 0 ? ProofKind.Range : ProofKind.Multi;
            BatchCase memory batch = currentCase32(513, 0, 2, proofKind, false);
            input = abi.encodeCall(this.checked, (batch));
            assertStageFailures(input, 12);
            assertStageFailures(input, 72);
            assertStageFailures(input, 104 + (batch.witness.pending == 0 ? 0 : 32));
        }
    }

    /// @dev A successful STATICCALL to an address without code has no digest and must fail closed.
    function test_RawEmptyTarget() public {
        BatchCase memory plain = operationsCase(13, sequence(0, 2), ProofKind.Range);
        QMDBCase memory current = currentBuilder.build(33, 0, hex"010203", true, 2);
        vm.etch(_hasher(), hex"");
        vm.expectRevert(LibMerkle.HashFailed.selector);
        this.checked(plain);
        vm.expectRevert(LibMerkle.HashFailed.selector);
        this.singleCurrentMembership(current, _hasher());
    }
}

contract LibQMDBHashMMBRawSha256Test is LibQMDBHashTest {
    function _family() internal pure override returns (LibMerkle.Family) {
        return LibMerkle.Family.MMB;
    }
}

contract LibQMDBHashMMRRawSha256Test is LibQMDBHashTest {
    function _family() internal pure override returns (LibMerkle.Family) {
        return LibMerkle.Family.MMR;
    }
}
