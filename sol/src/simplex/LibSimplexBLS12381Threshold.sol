// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.15;

import { LibBLS12381 as BLS } from "../certificate/LibBLS12381.sol";
import { LibBLS12381Threshold as Threshold } from "../certificate/LibBLS12381Threshold.sol";
import { LibSimplex as Simplex } from "./LibSimplex.sol";

/// @notice Verify Commonware Simplex BLS12-381 threshold certificates.
/// @dev The caller must choose the required vote kind and authenticate the group key for the signed epoch.
library LibSimplexBLS12381Threshold {
    /// @notice Verify a MinSig certificate for a Simplex vote.
    /// @param signature Uncompressed G1 coordinates, as accepted by Threshold.verifyMinSig.
    /// @param publicKey The trusted G2 group key for the subject's epoch.
    /// @param namespace The application's base namespace, without a vote suffix or length prefix.
    /// @param subject The vote reconstructed from trusted context and supplied fields.
    function verifyMinSig(
        bytes calldata signature,
        BLS.G2Point memory publicKey,
        bytes memory namespace,
        Simplex.Subject memory subject
    ) internal view returns (bool) {
        return Threshold.verifyMinSig(
            signature, publicKey, Simplex.namespace(namespace, subject.kind), Simplex.message(subject)
        );
    }

    /// @notice Verify a MinPk certificate for a Simplex vote.
    /// @param signature Uncompressed G2 coordinates, as accepted by Threshold.verifyMinPk.
    /// @param publicKey The trusted G1 group key for the subject's epoch.
    /// @param namespace The application's base namespace, without a vote suffix or length prefix.
    /// @param subject The vote reconstructed from trusted context and supplied fields.
    function verifyMinPk(
        bytes calldata signature,
        BLS.G1Point memory publicKey,
        bytes memory namespace,
        Simplex.Subject memory subject
    ) internal view returns (bool) {
        return Threshold.verifyMinPk(
            signature, publicKey, Simplex.namespace(namespace, subject.kind), Simplex.message(subject)
        );
    }
}
