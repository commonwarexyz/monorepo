// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.15;

import { LibMerkle } from "../src/merkle/LibMerkle.sol";
import { QMDBTest } from "./Common.t.sol";
import { LibQMDBCurrent } from "../src/qmdb/LibQMDBCurrent.sol";
import { LibQMDBCurrentMMB } from "../src/qmdb/LibQMDBCurrentMMB.sol";
import { LibQMDBCurrentMMR } from "../src/qmdb/LibQMDBCurrentMMR.sol";

abstract contract LibQMDBLifecycleTest is QMDBTest {
    struct Operation {
        bytes32 root;
        uint256 leaves;
        uint256 location;
        uint256 inactivePeaks;
        bytes chunk;
        bytes32 opsRoot;
        bytes32 pending;
        bytes32 partialDigest;
        bytes32[] digests;
        bytes operation;
    }

    struct Lifecycle {
        Operation before;
        Operation afterOverwrite;
        Operation excluded;
        Operation empty;
        bytes32 excludedKey;
        bytes32 emptyKey;
        uint256 retainedStart;
    }

    /// @dev Expose the calldata proof entrypoints with the fixture's 32-byte bitmap chunks.
    function verifyMembership(bytes32 root, bytes memory operation, LibQMDBCurrent.Proof calldata proof)
        external
        view
        returns (bool)
    {
        return _family() == LibMerkle.Family.MMB
            ? LibQMDBCurrentMMB.verify(root, operation, proof, 32, _hasher())
            : LibQMDBCurrentMMR.verify(root, operation, proof, 32, _hasher());
    }

    /// @dev Expose fixed-width exclusion with the fixture's 32-byte fields and bitmap chunks.
    function verifyExclusion(
        bytes32 root,
        bytes memory key,
        bytes memory operation,
        LibQMDBCurrent.Proof calldata proof
    ) external view returns (bool) {
        LibQMDBCurrent.ExclusionEncoding memory encoding =
            LibQMDBCurrent.ExclusionEncoding(LibQMDBCurrent.OperationEncoding.Fixed, 32, 32);
        return _family() == LibMerkle.Family.MMB
            ? LibQMDBCurrentMMB.verifyExclusion(root, key, operation, proof, encoding, 32, _hasher())
            : LibQMDBCurrentMMR.verifyExclusion(root, key, operation, proof, encoding, 32, _hasher());
    }

    /// @dev Map the Rust ABI tuple into the verifier's calldata proof structure.
    function _proof(Operation memory operation) internal pure returns (LibQMDBCurrent.Proof memory) {
        return LibQMDBCurrent.Proof(
            operation.leaves,
            operation.location,
            operation.inactivePeaks,
            operation.chunk,
            operation.opsRoot,
            operation.pending,
            operation.partialDigest,
            operation.digests
        );
    }

    /// @dev Verify persisted roots after overwrite, deletion, pruning, and populated and empty reopen cycles.
    function test_Differential_PersistentLifecycle() public {
        uint64[2] memory seeds = [uint64(71), type(uint64).max];
        for (uint256 i; i < seeds.length; ++i) {
            string[] memory args = new string[](7);
            args[0] = string.concat(vm.projectRoot(), "/../target/release/commonware-sol-fuzz");
            args[1] = "qmdb";
            args[2] = "lifecycle";
            args[3] = "--seed";
            args[4] = vm.toString(seeds[i]);
            args[5] = "--family";
            args[6] = _family() == LibMerkle.Family.MMB ? "mmb" : "mmr";
            Lifecycle memory c = abi.decode(_ffi(args), (Lifecycle));
            assertGt(c.retainedStart, 0, "pruning must remove stored operations");
            assertLt(c.empty.leaves, 2048, "bounded lifecycle");
            assertEq(c.afterOverwrite.root, c.excluded.root);
            assertNotEq(c.before.root, c.afterOverwrite.root);
            assertNotEq(c.afterOverwrite.root, c.empty.root);
            assertEq(c.before.operation[0], bytes1(0xd2));
            assertEq(c.empty.operation[0], bytes1(0xd3));
            assertTrue(this.verifyMembership(c.before.root, c.before.operation, _proof(c.before)), "initial membership");
            assertTrue(
                this.verifyMembership(c.afterOverwrite.root, c.afterOverwrite.operation, _proof(c.afterOverwrite)),
                "recovered membership"
            );
            assertTrue(
                this.verifyExclusion(
                    c.excluded.root, abi.encodePacked(c.excludedKey), c.excluded.operation, _proof(c.excluded)
                ),
                "deleted key exclusion"
            );
            assertTrue(
                this.verifyExclusion(c.empty.root, abi.encodePacked(c.emptyKey), c.empty.operation, _proof(c.empty)),
                "empty database exclusion"
            );
            assertTrue(
                this.verifyExclusion(c.empty.root, abi.encodePacked(c.excludedKey), c.empty.operation, _proof(c.empty)),
                "empty database excludes every key"
            );
            assertFalse(
                this.verifyExclusion(
                    c.excluded.root, abi.encodePacked(c.emptyKey), c.excluded.operation, _proof(c.excluded)
                ),
                "live key cannot be excluded"
            );
            c.before.root = c.afterOverwrite.root;
            assertFalse(
                this.verifyMembership(c.before.root, c.before.operation, _proof(c.before)),
                "stale proof under recovered root"
            );
            c.afterOverwrite.operation[33] ^= bytes1(uint8(1));
            assertFalse(
                this.verifyMembership(c.afterOverwrite.root, c.afterOverwrite.operation, _proof(c.afterOverwrite)),
                "wrong current value"
            );
        }
    }
}

abstract contract LibQMDBLifecycleMMBTest is LibQMDBLifecycleTest {
    function _family() internal pure override returns (LibMerkle.Family) {
        return LibMerkle.Family.MMB;
    }
}

contract LibQMDBLifecycleMMBKeccak256Test is LibQMDBLifecycleMMBTest {
    function _hasher() internal pure override returns (address) {
        return address(0);
    }
}

contract LibQMDBLifecycleMMBSha256Test is LibQMDBLifecycleMMBTest {
    function _hasher() internal pure override returns (address) {
        return address(2);
    }
}

abstract contract LibQMDBLifecycleMMRTest is LibQMDBLifecycleTest {
    function _family() internal pure override returns (LibMerkle.Family) {
        return LibMerkle.Family.MMR;
    }
}

contract LibQMDBLifecycleMMRKeccak256Test is LibQMDBLifecycleMMRTest {
    function _hasher() internal pure override returns (address) {
        return address(0);
    }
}

contract LibQMDBLifecycleMMRSha256Test is LibQMDBLifecycleMMRTest {
    function _hasher() internal pure override returns (address) {
        return address(2);
    }
}
