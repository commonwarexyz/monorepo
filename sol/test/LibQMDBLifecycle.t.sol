// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.15;

import { HashTest } from "./Common.t.sol";
import { LibQMDBCurrent } from "../src/qmdb/LibQMDBCurrent.sol";
import { LibQMDBCurrentMMB } from "../src/qmdb/LibQMDBCurrentMMB.sol";
import { LibQMDBCurrentMMR } from "../src/qmdb/LibQMDBCurrentMMR.sol";

contract LibQMDBLifecycleTest is HashTest {
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

    /// @dev Select the append family used by the database and verifier.
    function _mmb() internal pure virtual returns (bool) {
        return true;
    }

    /// @dev Expose the calldata proof entrypoints with the fixture's 32-byte bitmap chunks.
    function verify(
        bytes32 root,
        bytes memory operation,
        LibQMDBCurrent.Proof calldata proof,
        bool exclusion,
        bytes32 key
    ) external view returns (bool) {
        if (exclusion) {
            return _mmb()
                ? LibQMDBCurrentMMB.verifyExclusion(root, key, operation, proof, 32, _hasher())
                : LibQMDBCurrentMMR.verifyExclusion(root, key, operation, proof, 32, _hasher());
        }
        return _mmb()
            ? LibQMDBCurrentMMB.verify(root, operation, proof, 32, _hasher())
            : LibQMDBCurrentMMR.verify(root, operation, proof, 32, _hasher());
    }

    /// @dev Map the Rust ABI tuple into the verifier's calldata proof structure.
    function _verify(Operation memory operation, bool exclusion, bytes32 key) internal view returns (bool) {
        return this.verify(
            operation.root,
            operation.operation,
            LibQMDBCurrent.Proof(
                operation.leaves,
                operation.location,
                operation.inactivePeaks,
                operation.chunk,
                operation.opsRoot,
                operation.pending,
                operation.partialDigest,
                operation.digests
            ),
            exclusion,
            key
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
            args[6] = _mmb() ? "mmb" : "mmr";
            Lifecycle memory c = abi.decode(_ffi(args), (Lifecycle));
            assertGt(c.retainedStart, 0, "pruning must remove stored operations");
            assertLt(c.empty.leaves, 2048, "bounded lifecycle");
            assertEq(c.afterOverwrite.root, c.excluded.root);
            assertNotEq(c.before.root, c.afterOverwrite.root);
            assertNotEq(c.afterOverwrite.root, c.empty.root);
            assertEq(c.before.operation[0], bytes1(0xd2));
            assertEq(c.empty.operation[0], bytes1(0xd3));
            assertTrue(_verify(c.before, false, 0), "initial membership");
            assertTrue(_verify(c.afterOverwrite, false, 0), "recovered membership");
            assertTrue(_verify(c.excluded, true, c.excludedKey), "deleted key exclusion");
            assertTrue(_verify(c.empty, true, c.emptyKey), "empty database exclusion");
            assertTrue(_verify(c.empty, true, c.excludedKey), "empty database excludes every key");
            assertFalse(_verify(c.excluded, true, c.emptyKey), "live key cannot be excluded");
            c.before.root = c.afterOverwrite.root;
            assertFalse(_verify(c.before, false, 0), "stale proof under recovered root");
            c.afterOverwrite.operation[33] ^= bytes1(uint8(1));
            assertFalse(_verify(c.afterOverwrite, false, 0), "wrong current value");
        }
    }
}

contract LibQMDBLifecycleSha256Test is LibQMDBLifecycleTest {
    /// @dev Select the SHA-256 precompile and matching Rust database hasher.
    function _hasher() internal pure override returns (address) {
        return address(2);
    }
}

contract LibQMDBLifecycleMMRTest is LibQMDBLifecycleTest {
    /// @dev Select the MMR append family for the complete lifecycle.
    function _mmb() internal pure override returns (bool) {
        return false;
    }
}

contract LibQMDBLifecycleMMRSha256Test is LibQMDBLifecycleMMRTest {
    /// @dev Select the SHA-256 precompile and matching Rust database hasher.
    function _hasher() internal pure override returns (address) {
        return address(2);
    }
}
