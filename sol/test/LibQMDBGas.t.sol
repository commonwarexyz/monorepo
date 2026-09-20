// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.15;

import { LibMerkle } from "../src/merkle/LibMerkle.sol";
import { ProofKind, QMDBTest, RootKind } from "./Common.t.sol";
import { BatchCase, LibQMDBBatchTest } from "./LibQMDBBatch.t.sol";
import { LibQMDBCurrentTest, QMDBCase } from "./LibQMDBCurrent.t.sol";
import { LibQMDBCommon } from "../src/qmdb/LibQMDBCommon.sol";
import { LibQMDBCurrent } from "../src/qmdb/LibQMDBCurrent.sol";
import { LibQMDBAnyMMB } from "../src/qmdb/LibQMDBAnyMMB.sol";
import { LibQMDBAnyMMR } from "../src/qmdb/LibQMDBAnyMMR.sol";
import { LibQMDBKeylessMMB } from "../src/qmdb/LibQMDBKeylessMMB.sol";
import { LibQMDBKeylessMMR } from "../src/qmdb/LibQMDBKeylessMMR.sol";
import { LibQMDBImmutableMMB } from "../src/qmdb/LibQMDBImmutableMMB.sol";
import { LibQMDBImmutableMMR } from "../src/qmdb/LibQMDBImmutableMMR.sol";
import { LibQMDBCurrentMMB } from "../src/qmdb/LibQMDBCurrentMMB.sol";
import { LibQMDBCurrentMMR } from "../src/qmdb/LibQMDBCurrentMMR.sol";

struct QMDBGasSingleCase {
    bytes32 root;
    bytes operation;
    LibQMDBCommon.Proof proof;
}

/// @dev Reuses independent native fixture builders outside each measured verifier frame.
abstract contract LibQMDBGasTest is QMDBTest {
    LibQMDBBatchTest internal batchBuilder;
    LibQMDBCurrentTest internal currentBuilder;

    function verifyAny(QMDBGasSingleCase calldata c) external view virtual returns (bool);

    function verifyAnyRange(BatchCase calldata c) external view virtual returns (bool);

    function verifyAnyMulti(BatchCase calldata c) external view virtual returns (bool);

    function verifyKeyless(QMDBGasSingleCase calldata c) external view virtual returns (bool);

    function verifyKeylessRange(BatchCase calldata c) external view virtual returns (bool);

    function verifyKeylessMulti(BatchCase calldata c) external view virtual returns (bool);

    function verifyImmutable(QMDBGasSingleCase calldata c) external view virtual returns (bool);

    function verifyImmutableRange(BatchCase calldata c) external view virtual returns (bool);

    function verifyImmutableMulti(BatchCase calldata c) external view virtual returns (bool);

    function verifyCurrent(QMDBCase calldata c) external view virtual returns (bool);

    function verifyCurrentRange(BatchCase calldata c) external view virtual returns (bool);

    function verifyCurrentMulti(BatchCase calldata c) external view virtual returns (bool);

    function verifyCurrentExclusion(QMDBCase calldata c, bytes calldata key, LibQMDBCurrent.Schema calldata schema)
        external
        view
        virtual
        returns (bool);

    function setUp() public {
        string memory family = _family() == LibMerkle.Family.MMB ? "MMB" : "MMR";
        string memory hash = _hasher() == address(0) ? "Keccak256" : "Sha256";
        batchBuilder =
            LibQMDBBatchTest(deployCode(string.concat("LibQMDBBatch.t.sol:LibQMDBBatch", family, hash, "Test")));
        currentBuilder = LibQMDBCurrentTest(
            deployCode(string.concat("LibQMDBCurrent.t.sol:LibQMDBCurrent", family, hash, "Test"))
        );
    }

    function test_GasAny() public {
        QMDBGasSingleCase memory single = _singletonCase();
        bool valid = this.verifyAny(single);
        vm.snapshotGasLastFrame(_qmdbGroup("Any"), "singleton-383-last-opaque-12-byte-operation");
        assertTrue(valid);

        BatchCase memory range = batchBuilder.operationsCase(383, _sequence(170, 34), ProofKind.Range);
        valid = this.verifyAnyRange(range);
        vm.snapshotGasLastFrame(_qmdbGroup("Any"), "range-383-middle-34-opaque-4-to-37-byte-operations");
        assertTrue(valid);

        BatchCase memory multi = batchBuilder.operationsCase(383, _sparseLocations(), ProofKind.Multi);
        valid = this.verifyAnyMulti(multi);
        vm.snapshotGasLastFrame(_qmdbGroup("Any"), "sparse-383-three-opaque-4-25-12-byte-operations");
        assertTrue(valid);
    }

    function test_GasKeyless() public {
        QMDBGasSingleCase memory single = _singletonCase();
        bool valid = this.verifyKeyless(single);
        vm.snapshotGasLastFrame(_qmdbGroup("Keyless"), "singleton-383-last-opaque-12-byte-operation");
        assertTrue(valid);

        BatchCase memory range = batchBuilder.operationsCase(383, _sequence(170, 34), ProofKind.Range);
        valid = this.verifyKeylessRange(range);
        vm.snapshotGasLastFrame(_qmdbGroup("Keyless"), "range-383-middle-34-opaque-4-to-37-byte-operations");
        assertTrue(valid);

        BatchCase memory multi = batchBuilder.operationsCase(383, _sparseLocations(), ProofKind.Multi);
        valid = this.verifyKeylessMulti(multi);
        vm.snapshotGasLastFrame(_qmdbGroup("Keyless"), "sparse-383-three-opaque-4-25-12-byte-operations");
        assertTrue(valid);
    }

    function test_GasImmutable() public {
        QMDBGasSingleCase memory single = _singletonCase();
        bool valid = this.verifyImmutable(single);
        vm.snapshotGasLastFrame(_qmdbGroup("Immutable"), "singleton-383-last-opaque-12-byte-operation");
        assertTrue(valid);

        BatchCase memory range = batchBuilder.operationsCase(383, _sequence(170, 34), ProofKind.Range);
        valid = this.verifyImmutableRange(range);
        vm.snapshotGasLastFrame(_qmdbGroup("Immutable"), "range-383-middle-34-opaque-4-to-37-byte-operations");
        assertTrue(valid);

        BatchCase memory multi = batchBuilder.operationsCase(383, _sparseLocations(), ProofKind.Multi);
        valid = this.verifyImmutableMulti(multi);
        vm.snapshotGasLastFrame(_qmdbGroup("Immutable"), "sparse-383-three-opaque-4-25-12-byte-operations");
        assertTrue(valid);
    }

    function test_GasCurrent() public {
        bytes memory operation = abi.encodePacked(bytes1(0xd2), bytes32(uint256(10)), bytes32(uint256(20)));
        QMDBCase memory single = currentBuilder.build(383, 1, operation, true, 32);
        bool valid = this.verifyCurrent(single);
        vm.snapshotGasLastFrame(_currentGroup(), "active-singleton-383-grafted-opaque-65-byte-operation");
        assertTrue(valid);

        BatchCase memory range =
            batchBuilder.buildTree(383, _sequence(239, 34), ProofKind.Range, RootKind.Current, _activityChunks(383));
        valid = this.verifyCurrentRange(range);
        vm.snapshotGasLastFrame(_currentGroup(), "range-383-cross-chunk-34-opaque-4-to-37-byte-operations");
        assertTrue(valid);

        BatchCase memory multi =
            batchBuilder.buildTree(383, _sparseLocations(), ProofKind.Multi, RootKind.Current, _activityChunks(383));
        valid = this.verifyCurrentMulti(multi);
        vm.snapshotGasLastFrame(_currentGroup(), "historical-ops-multi-383-three-opaque-4-25-12-byte-operations");
        assertTrue(valid);

        bytes memory key = abi.encodePacked(bytes32(uint256(15)));
        LibQMDBCurrent.Schema memory schema = LibQMDBCurrent.Schema(LibQMDBCurrent.Encoding.Fixed, 32, 32);
        operation = abi.encodePacked(bytes1(0xd2), bytes32(uint256(10)), bytes32(uint256(1)), bytes32(uint256(20)));
        single = currentBuilder.build(383, 1, operation, true, 32);
        valid = this.verifyCurrentExclusion(single, key, schema);
        vm.snapshotGasLastFrame(_currentGroup(), "fixed-k32-v32-exclusion-383-grafted-interval-97-byte-operation");
        assertTrue(valid);

        schema = LibQMDBCurrent.Schema(LibQMDBCurrent.Encoding.Variable, type(uint256).max, type(uint256).max);
        operation = abi.encodePacked(
            bytes1(0xd2),
            bytes1(0x20),
            bytes32(uint256(10)),
            bytes1(0x20),
            bytes32(uint256(1)),
            bytes1(0x20),
            bytes32(uint256(20))
        );
        single = currentBuilder.build(383, 1, operation, true, 32);
        valid = this.verifyCurrentExclusion(single, key, schema);
        vm.snapshotGasLastFrame(
            _currentGroup(), "variable-vector-k32-v32-exclusion-383-grafted-interval-100-byte-operation"
        );
        assertTrue(valid);

        key = abi.encodePacked(bytes32(uint256(7)));
        schema = LibQMDBCurrent.Schema(LibQMDBCurrent.Encoding.Fixed, 32, 0);
        single = currentBuilder.build(1, 0, abi.encodePacked(hex"d300", uint64(0), new bytes(55)), true, 32);
        valid = this.verifyCurrentExclusion(single, key, schema);
        vm.snapshotGasLastFrame(_currentGroup(), "fixed-k32-v0-exclusion-empty-database-commit-65-byte-operation");
        assertTrue(valid);

        schema = LibQMDBCurrent.Schema(LibQMDBCurrent.Encoding.Variable, type(uint256).max, type(uint256).max);
        single = currentBuilder.build(1, 0, hex"d30000", true, 32);
        valid = this.verifyCurrentExclusion(single, key, schema);
        vm.snapshotGasLastFrame(
            _currentGroup(), "variable-vector-k32-v0-exclusion-empty-database-commit-3-byte-operation"
        );
        assertTrue(valid);
    }

    function _singletonCase() internal view returns (QMDBGasSingleCase memory c) {
        BatchCase memory batch = batchBuilder.operationsCase(383, _sequence(382, 1), ProofKind.Range);
        c.root = batch.root;
        c.operation = batch.operations[0];
        c.proof = LibQMDBCommon.Proof(
            batch.range.leaves, batch.range.start, batch.range.inactivePeaks, batch.range.digests
        );
    }

    function _qmdbGroup(string memory facade) internal pure returns (string memory) {
        return string.concat(
            "QMDB",
            facade,
            _family() == LibMerkle.Family.MMB ? "MMB" : "MMR",
            _hasher() == address(0) ? "Keccak256" : "Sha256"
        );
    }

    function _currentGroup() internal pure returns (string memory) {
        return string.concat(_qmdbGroup("Current"), "ChunkBytes32");
    }

    function _sequence(uint256 start, uint256 count) internal pure returns (uint256[] memory locations) {
        locations = new uint256[](count);
        for (uint256 i; i < count; ++i) {
            locations[i] = start + i;
        }
    }

    function _sparseLocations() internal pure returns (uint256[] memory locations) {
        locations = new uint256[](3);
        locations[0] = 0;
        locations[1] = 191;
        locations[2] = 382;
    }

    function _activityChunks(uint256 leaves) internal pure returns (bytes32[] memory chunks) {
        chunks = new bytes32[]((leaves + 255) / 256);
        for (uint256 i; i < leaves; ++i) {
            if (i % 3 != 0) chunks[i / 256] |= bytes32(uint256(1) << (248 - ((i % 256) / 8) * 8 + i % 8));
        }
    }
}

abstract contract LibQMDBGasMMBTest is LibQMDBGasTest {
    function _family() internal pure override returns (LibMerkle.Family) {
        return LibMerkle.Family.MMB;
    }

    function verifyAny(QMDBGasSingleCase calldata c) external view override returns (bool) {
        return LibQMDBAnyMMB.verify(c.root, c.operation, c.proof, _hasher());
    }

    function verifyAnyRange(BatchCase calldata c) external view override returns (bool) {
        return LibQMDBAnyMMB.verifyRange(c.root, c.operations, c.range, _hasher());
    }

    function verifyAnyMulti(BatchCase calldata c) external view override returns (bool) {
        return LibQMDBAnyMMB.verifyMulti(c.root, c.operations, c.multi, _hasher());
    }

    function verifyKeyless(QMDBGasSingleCase calldata c) external view override returns (bool) {
        return LibQMDBKeylessMMB.verify(c.root, c.operation, c.proof, _hasher());
    }

    function verifyKeylessRange(BatchCase calldata c) external view override returns (bool) {
        return LibQMDBKeylessMMB.verifyRange(c.root, c.operations, c.range, _hasher());
    }

    function verifyKeylessMulti(BatchCase calldata c) external view override returns (bool) {
        return LibQMDBKeylessMMB.verifyMulti(c.root, c.operations, c.multi, _hasher());
    }

    function verifyImmutable(QMDBGasSingleCase calldata c) external view override returns (bool) {
        return LibQMDBImmutableMMB.verify(c.root, c.operation, c.proof, _hasher());
    }

    function verifyImmutableRange(BatchCase calldata c) external view override returns (bool) {
        return LibQMDBImmutableMMB.verifyRange(c.root, c.operations, c.range, _hasher());
    }

    function verifyImmutableMulti(BatchCase calldata c) external view override returns (bool) {
        return LibQMDBImmutableMMB.verifyMulti(c.root, c.operations, c.multi, _hasher());
    }

    function verifyCurrent(QMDBCase calldata c) external view override returns (bool) {
        return LibQMDBCurrentMMB.verify(c.root, c.operation, c.proof, c.chunkBytes, _hasher());
    }

    function verifyCurrentRange(BatchCase calldata c) external view override returns (bool) {
        return LibQMDBCurrentMMB.verifyRange(c.root, c.operations, c.currentRange, c.chunkBytes, _hasher());
    }

    function verifyCurrentMulti(BatchCase calldata c) external view override returns (bool) {
        return LibQMDBCurrentMMB.verifyOpsMulti(c.root, c.operations, c.multi, c.witness, c.chunkBytes, _hasher());
    }

    function verifyCurrentExclusion(QMDBCase calldata c, bytes calldata key, LibQMDBCurrent.Schema calldata schema)
        external
        view
        override
        returns (bool)
    {
        return LibQMDBCurrentMMB.verifyExclusion(c.root, key, c.operation, c.proof, schema, c.chunkBytes, _hasher());
    }
}

contract LibQMDBGasMMBKeccak256Test is LibQMDBGasMMBTest {
    function _hasher() internal pure override returns (address) {
        return address(0);
    }
}

contract LibQMDBGasMMBSha256Test is LibQMDBGasMMBTest {
    function _hasher() internal pure override returns (address) {
        return address(2);
    }
}

abstract contract LibQMDBGasMMRTest is LibQMDBGasTest {
    function _family() internal pure override returns (LibMerkle.Family) {
        return LibMerkle.Family.MMR;
    }

    function verifyAny(QMDBGasSingleCase calldata c) external view override returns (bool) {
        return LibQMDBAnyMMR.verify(c.root, c.operation, c.proof, _hasher());
    }

    function verifyAnyRange(BatchCase calldata c) external view override returns (bool) {
        return LibQMDBAnyMMR.verifyRange(c.root, c.operations, c.range, _hasher());
    }

    function verifyAnyMulti(BatchCase calldata c) external view override returns (bool) {
        return LibQMDBAnyMMR.verifyMulti(c.root, c.operations, c.multi, _hasher());
    }

    function verifyKeyless(QMDBGasSingleCase calldata c) external view override returns (bool) {
        return LibQMDBKeylessMMR.verify(c.root, c.operation, c.proof, _hasher());
    }

    function verifyKeylessRange(BatchCase calldata c) external view override returns (bool) {
        return LibQMDBKeylessMMR.verifyRange(c.root, c.operations, c.range, _hasher());
    }

    function verifyKeylessMulti(BatchCase calldata c) external view override returns (bool) {
        return LibQMDBKeylessMMR.verifyMulti(c.root, c.operations, c.multi, _hasher());
    }

    function verifyImmutable(QMDBGasSingleCase calldata c) external view override returns (bool) {
        return LibQMDBImmutableMMR.verify(c.root, c.operation, c.proof, _hasher());
    }

    function verifyImmutableRange(BatchCase calldata c) external view override returns (bool) {
        return LibQMDBImmutableMMR.verifyRange(c.root, c.operations, c.range, _hasher());
    }

    function verifyImmutableMulti(BatchCase calldata c) external view override returns (bool) {
        return LibQMDBImmutableMMR.verifyMulti(c.root, c.operations, c.multi, _hasher());
    }

    function verifyCurrent(QMDBCase calldata c) external view override returns (bool) {
        return LibQMDBCurrentMMR.verify(c.root, c.operation, c.proof, c.chunkBytes, _hasher());
    }

    function verifyCurrentRange(BatchCase calldata c) external view override returns (bool) {
        return LibQMDBCurrentMMR.verifyRange(c.root, c.operations, c.currentRange, c.chunkBytes, _hasher());
    }

    function verifyCurrentMulti(BatchCase calldata c) external view override returns (bool) {
        return LibQMDBCurrentMMR.verifyOpsMulti(c.root, c.operations, c.multi, c.witness, c.chunkBytes, _hasher());
    }

    function verifyCurrentExclusion(QMDBCase calldata c, bytes calldata key, LibQMDBCurrent.Schema calldata schema)
        external
        view
        override
        returns (bool)
    {
        return LibQMDBCurrentMMR.verifyExclusion(c.root, key, c.operation, c.proof, schema, c.chunkBytes, _hasher());
    }
}

contract LibQMDBGasMMRKeccak256Test is LibQMDBGasMMRTest {
    function _hasher() internal pure override returns (address) {
        return address(0);
    }
}

contract LibQMDBGasMMRSha256Test is LibQMDBGasMMRTest {
    function _hasher() internal pure override returns (address) {
        return address(2);
    }
}
