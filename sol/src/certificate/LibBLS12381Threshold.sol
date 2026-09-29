// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.15;

import { LibBLS12381 as BLS } from "./LibBLS12381.sol";

/// @notice Verify Commonware BLS12-381 threshold certificates with EIP-2537.
/// @dev The caller must authenticate the committee group key and select the signing namespace.
library LibBLS12381Threshold {
    /// @notice Verify a recovered MinSig threshold certificate over a namespaced message.
    /// @param signature Uncompressed G1 coordinates `x || y`, each 48 bytes without padding.
    /// @param publicKey The trusted G2 committee group key.
    /// @param namespace The signing namespace, without a length prefix.
    /// @param message The encoded subject, without namespace framing.
    /// @return valid Whether the signature is valid. Invalid lengths, points, and infinity return false.
    function verifyMinSig(
        bytes calldata signature,
        BLS.G2Point memory publicKey,
        bytes memory namespace,
        bytes memory message
    ) internal view returns (bool valid) {
        return BLS.verifyMinSig(signature, publicKey, namespace, message);
    }

    /// @notice Verify a recovered MinPk threshold certificate over a namespaced message.
    /// @param signature Uncompressed G2 coordinates `x.c0 || x.c1 || y.c0 || y.c1`, each 48 bytes.
    /// @param publicKey The trusted G1 committee group key.
    /// @param namespace The signing namespace, without a length prefix.
    /// @param message The encoded subject, without namespace framing.
    /// @return valid Whether the signature is valid. Invalid lengths, points, and infinity return false.
    function verifyMinPk(
        bytes calldata signature,
        BLS.G1Point memory publicKey,
        bytes memory namespace,
        bytes memory message
    ) internal view returns (bool valid) {
        return BLS.verifyMinPk(signature, publicKey, namespace, message);
    }
}
