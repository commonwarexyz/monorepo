// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.15;

import { Common } from "./Common.sol";
import { Current } from "./Current.sol";

/// @notice Verify active operations, historical operation inclusion and key exclusion in a current MMB QMDB.
/// @dev The caller authenticates the root, schema, bitmap chunk byte size and hash target.
/// Uses QMDB's backward peak fold and big-endian position and count encodings.
/// Bitmap chunks must have a nonzero power-of-two byte length below `2^60`.
/// Nonzero hash targets receive raw bytes via `STATICCALL` and must return exactly 32 bytes.
/// A failed call or another return length reverts with `HashFailed()`.
library LibQMDBCurrentMMB {
    /// @notice Verify an encoded operation and its active bit against a trusted current MMB root.
    /// @param root Authenticated current QMDB MMB root with the specified schema and chunk size.
    /// @param operation Exact Commonware operation encoding, including codec tags, padding and length prefixes.
    /// @param proof Single-operation membership proof with an activity chunk.
    /// @param chunkBytes Trusted bitmap chunk byte size of the authenticated database.
    /// @param hasher Trusted raw hash target, or `address(0)` for native Keccak256.
    /// @return True when the active operation reconstructs `root` and consumes every digest.
    function verify(
        bytes32 root,
        bytes memory operation,
        Current.Proof calldata proof,
        uint256 chunkBytes,
        address hasher
    ) internal view returns (bool) {
        return Current.verify(root, operation, proof, true, chunkBytes, hasher);
    }

    /// @notice Verify operation bytes and activity status for a current MMB range.
    /// @dev Inactive operations are valid. Every touched chunk is authenticated.
    /// Chunks are packed in increasing chunk order, each with `chunkBytes` bytes.
    /// @param root Authenticated current QMDB MMB root with the specified schema and chunk size.
    /// @param operations Exact Commonware operation encodings in consecutive location order.
    /// @param proof Range proof containing every touched activity chunk.
    /// @param chunkBytes Trusted bitmap chunk byte size of the authenticated database.
    /// @param hasher Trusted raw hash target, or `address(0)` for native Keccak256.
    /// @return True when the range and its activity chunks reconstruct `root` and consume every digest.
    function verifyRange(
        bytes32 root,
        bytes[] memory operations,
        Current.RangeProof calldata proof,
        uint256 chunkBytes,
        address hasher
    ) internal view returns (bool) {
        return Current.verifyRange(root, operations, proof, true, chunkBytes, hasher);
    }

    /// @notice Verify historical operation inclusion under a canonical current MMB root.
    /// @dev The witness authenticates the operation root without establishing activity of selected operations.
    /// Proof witnesses are in increasing physical position order.
    /// @param root Authenticated current QMDB MMB root with the specified schema and chunk size.
    /// @param operations Exact Commonware operation encodings corresponding to `proof.locations`.
    /// @param proof Sparse operation proof from the same snapshot as `witness`.
    /// @param witness Current root commitments authenticating the operation root.
    /// @param chunkBytes Trusted bitmap chunk byte size of the authenticated database.
    /// @param hasher Trusted raw hash target, or `address(0)` for native Keccak256.
    /// @return True when the selected operations belong to the operation root authenticated under `root`.
    function verifyOpsMulti(
        bytes32 root,
        bytes[] memory operations,
        Common.MultiProof calldata proof,
        Current.OpsRootWitness calldata witness,
        uint256 chunkBytes,
        address hasher
    ) internal view returns (bool) {
        return Current.verifyOpsMulti(root, operations, proof, witness, true, chunkBytes, hasher);
    }

    /// @notice Verify key exclusion against a trusted ordered current MMB root.
    /// @dev The database uses 32-byte keys and fixed values of size `V`. Operations have `65 + V` bytes.
    /// Updates encode tag, key, value, then next key. Commits encode tag, metadata flag,
    /// `V` metadata bytes, big-endian `uint64` floor, then 55 zero bytes. The trusted schema determines `V`.
    /// @param root Authenticated current QMDB MMB root with the specified schema and chunk size.
    /// @param key Raw key whose absence is being proven.
    /// @param operation Exact encoded adjacent-key update or empty-database commit.
    /// @param proof Single-operation membership proof with an activity chunk.
    /// @param chunkBytes Trusted bitmap chunk byte size of the authenticated database.
    /// @param hasher Trusted raw hash target, or `address(0)` for native Keccak256.
    /// @return True when the active operation proves that `key` is absent under `root`.
    function verifyExclusion(
        bytes32 root,
        bytes32 key,
        bytes memory operation,
        Current.Proof calldata proof,
        uint256 chunkBytes,
        address hasher
    ) internal view returns (bool) {
        return Current.verifyExclusion(root, key, operation, proof, true, chunkBytes, hasher);
    }

    /// @notice Verify ordered key exclusion under a current MMB root with variable operation encoding.
    /// @dev Keys use raw byte lexicographic ordering. The trusted schema selects fixed-width fields
    /// or byte vectors with canonical unsigned 32-bit varint lengths using `Current.VARIABLE_SIZE`.
    /// @param root Authenticated current QMDB MMB root with the specified schema and chunk size.
    /// @param key Raw key whose absence is being proven.
    /// @param operation Exact encoded adjacent-key update or empty-database commit.
    /// @param proof Single-operation membership proof with an activity chunk.
    /// @param encoding Trusted key and value encoding configuration bound to `root`.
    /// @param chunkBytes Trusted bitmap chunk byte size of the authenticated database.
    /// @param hasher Trusted raw hash target, or `address(0)` for native Keccak256.
    /// @return True when the active operation proves that `key` is absent under `root`.
    function verifyExclusionVariable(
        bytes32 root,
        bytes memory key,
        bytes memory operation,
        Current.Proof calldata proof,
        Current.ExclusionEncoding memory encoding,
        uint256 chunkBytes,
        address hasher
    ) internal view returns (bool) {
        return Current.verifyExclusionVariable(root, key, operation, proof, encoding, true, chunkBytes, hasher);
    }
}
