// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.15;

import { LibBLS12381 as BLS } from "../certificate/LibBLS12381.sol";
import { LibBLS12381Multisig as Multisig } from "../certificate/LibBLS12381Multisig.sol";
import { LibSimplex as Simplex } from "./LibSimplex.sol";

/// @notice Verify Commonware Simplex BLS12-381 multisignature certificates.
/// @dev The caller must choose the required vote kind and authenticate the committee for the signed epoch.
library LibSimplexBLS12381Multisig {
    /// @notice Verify a MinSig multisignature for a Simplex vote.
    /// @dev `publicKeys` must be the trusted ordered committee for `subject.epoch`, with distinct keys,
    /// authenticated identity-to-key bindings, and every key and proof of possession validated at
    /// registration. A non-empty committee requires `n - floor((n - 1) / 3)` signers.
    /// @param signature Uncompressed aggregate G1 coordinates, as accepted by Multisig.verifyMinSig.
    /// @param signers Little-endian signer bitmap over `publicKeys`.
    /// @param publicKeys The trusted ordered G2 committee for the subject's epoch.
    /// @param namespace The application's base namespace, without a vote suffix or length prefix.
    /// @param subject The vote reconstructed from trusted context and supplied fields.
    function verifyMinSig(
        bytes calldata signature,
        bytes calldata signers,
        BLS.G2Point[] memory publicKeys,
        bytes memory namespace,
        Simplex.Subject memory subject
    ) internal view returns (bool) {
        uint256 count = publicKeys.length;
        if (count == 0) return false;
        uint256 quorum = _quorum(count);
        return Multisig.verifyMinSig(
            signature, signers, publicKeys, quorum, Simplex.namespace(namespace, subject.kind), Simplex.message(subject)
        );
    }

    /// @notice Verify a MinPk multisignature for a Simplex vote.
    /// @dev `publicKeys` must be the trusted ordered committee for `subject.epoch`, with distinct keys,
    /// authenticated identity-to-key bindings, and every key and proof of possession validated at
    /// registration. A non-empty committee requires `n - floor((n - 1) / 3)` signers.
    /// @param signature Uncompressed aggregate G2 coordinates, as accepted by Multisig.verifyMinPk.
    /// @param signers Little-endian signer bitmap over `publicKeys`.
    /// @param publicKeys The trusted ordered G1 committee for the subject's epoch.
    /// @param namespace The application's base namespace, without a vote suffix or length prefix.
    /// @param subject The vote reconstructed from trusted context and supplied fields.
    function verifyMinPk(
        bytes calldata signature,
        bytes calldata signers,
        BLS.G1Point[] memory publicKeys,
        bytes memory namespace,
        Simplex.Subject memory subject
    ) internal view returns (bool) {
        uint256 count = publicKeys.length;
        if (count == 0) return false;
        uint256 quorum = _quorum(count);
        return Multisig.verifyMinPk(
            signature, signers, publicKeys, quorum, Simplex.namespace(namespace, subject.kind), Simplex.message(subject)
        );
    }

    function _quorum(uint256 count) private pure returns (uint256) {
        return count - (count - 1) / 3;
    }
}
