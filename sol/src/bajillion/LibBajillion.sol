// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.15;

import { LibQMDB } from "../qmdb/LibQMDB.sol";

/// @notice Verify Bajillion frozen-balance membership proofs.
/// @dev The settlement contract authenticates the frozen root, authorizes the account's
/// withdrawal recipient and records claimed exits. Membership alone does not authorize payment.
library LibBajillion {
    /// @notice Verify a positive account balance under an authenticated frozen QMDB root.
    /// @param root Frozen balance root selected by the settlement contract.
    /// @param account Canonical 32-byte account public key.
    /// @param balance Claimed positive balance in the settlement asset's units.
    /// @param nextKey Successor key from the ordered membership proof.
    /// @param proof Current MMB QMDB proof with a 32-byte activity bitmap chunk.
    /// @param hasher Trusted raw hash target matching the database, zero for Keccak256 or `address(2)` for SHA256.
    /// @return True when the account has exactly `balance` under `root`.
    function verifyBalance(
        bytes32 root,
        bytes32 account,
        uint64 balance,
        bytes32 nextKey,
        LibQMDB.Proof calldata proof,
        address hasher
    ) internal view returns (bool) {
        if (balance == 0) return false;
        return LibQMDB.verify(root, abi.encodePacked(bytes1(0xd2), account, balance, nextKey), proof, hasher);
    }
}
