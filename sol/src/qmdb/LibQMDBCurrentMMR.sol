// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.15;

import { LibMerkle } from "../merkle/LibMerkle.sol";
import { LibQMDBCommon } from "./LibQMDBCommon.sol";
import { LibQMDBCurrent } from "./LibQMDBCurrent.sol";

/// @notice Verify active operations, historical operation inclusion and key exclusion in a current MMR QMDB.
/// @dev The caller authenticates the root, schema, bitmap chunk byte size and hash target.
/// Uses QMDB's backward peak fold and big-endian position and count encodings.
/// Bitmap chunks must have a nonzero power-of-two byte length below `2^60`.
/// Nonzero hash targets receive raw bytes via `STATICCALL` and must return exactly 32 bytes.
/// A failed call or another return length reverts with `HashFailed()`.
library LibQMDBCurrentMMR {
    /// @notice Verify an encoded operation and its active bit against a trusted current MMR root.
    /// @dev The caller uses the database schema to bind operation bytes to the expected key and value.
    /// @param root Authenticated current QMDB MMR root with the specified schema and chunk size.
    /// @param operation Exact Commonware operation encoding, including codec tags, padding and length prefixes.
    /// @param proof Single-operation membership proof with an activity chunk.
    /// @param chunkBytes Trusted bitmap chunk byte size of the authenticated database.
    /// @param hasher Trusted raw hash target, or `address(0)` for native Keccak256.
    /// @return True when the active operation reconstructs `root` and consumes every digest.
    function verify(
        bytes32 root,
        bytes memory operation,
        LibQMDBCurrent.Proof calldata proof,
        uint256 chunkBytes,
        address hasher
    ) internal view returns (bool) {
        return LibQMDBCurrent.verify(root, operation, proof, LibMerkle.Family.MMR, chunkBytes, hasher);
    }

    /// @notice Verify operation bytes and activity status for a current MMR range.
    /// @dev Inactive operations are valid. Every touched chunk is authenticated.
    /// Chunks are packed in increasing chunk order, each with `chunkBytes` bytes.
    /// @param root Authenticated current QMDB MMR root with the specified schema and chunk size.
    /// @param operations Exact Commonware operation encodings in consecutive location order.
    /// @param proof Range proof containing every touched activity chunk.
    /// @param chunkBytes Trusted bitmap chunk byte size of the authenticated database.
    /// @param hasher Trusted raw hash target, or `address(0)` for native Keccak256.
    /// @return True when the range and its activity chunks reconstruct `root` and consume every digest.
    function verifyRange(
        bytes32 root,
        bytes[] memory operations,
        LibQMDBCurrent.RangeProof calldata proof,
        uint256 chunkBytes,
        address hasher
    ) internal view returns (bool) {
        return LibQMDBCurrent.verifyRange(root, operations, proof, LibMerkle.Family.MMR, chunkBytes, hasher);
    }

    /// @notice Verify historical operation inclusion under a canonical current MMR root.
    /// @dev The witness authenticates the operation root without establishing activity of selected operations.
    /// Proof witnesses are in increasing physical position order.
    /// @param root Authenticated current QMDB MMR root with the specified schema and chunk size.
    /// @param operations Exact Commonware operation encodings corresponding to `proof.locations`.
    /// @param proof Sparse operation proof from the same snapshot as `witness`.
    /// @param witness Current root commitments authenticating the operation root.
    /// @param chunkBytes Trusted bitmap chunk byte size of the authenticated database.
    /// @param hasher Trusted raw hash target, or `address(0)` for native Keccak256.
    /// @return True when the selected operations belong to the operation root authenticated under `root`.
    function verifyOpsMulti(
        bytes32 root,
        bytes[] memory operations,
        LibQMDBCommon.MultiProof calldata proof,
        LibQMDBCurrent.OpsRootWitness calldata witness,
        uint256 chunkBytes,
        address hasher
    ) internal view returns (bool) {
        return LibQMDBCurrent.verifyOpsMulti(root, operations, proof, witness, LibMerkle.Family.MMR, chunkBytes, hasher);
    }

    /// @notice Verify ordered key exclusion under a trusted current MMR root.
    /// @dev The trusted schema selects operation framing and fixed-width or length-prefixed fields.
    /// Keys use raw byte lexicographic ordering.
    /// @param root Authenticated current QMDB MMR root with the specified schema and chunk size.
    /// @param key Raw key whose absence is being proven.
    /// @param operation Exact encoded adjacent-key update or empty-database commit.
    /// @param proof Single-operation membership proof with an activity chunk.
    /// @param schema Trusted operation framing and field sizes bound to `root`.
    /// @param chunkBytes Trusted bitmap chunk byte size of the authenticated database.
    /// @param hasher Trusted raw hash target, or `address(0)` for native Keccak256.
    /// @return True when the active operation proves that `key` is absent under `root`.
    function verifyExclusion(
        bytes32 root,
        bytes memory key,
        bytes memory operation,
        LibQMDBCurrent.Proof calldata proof,
        LibQMDBCurrent.Schema memory schema,
        uint256 chunkBytes,
        address hasher
    ) internal view returns (bool) {
        return LibQMDBCurrent.verifyExclusion(
            root, key, operation, proof, schema, LibMerkle.Family.MMR, chunkBytes, hasher
        );
    }
}
