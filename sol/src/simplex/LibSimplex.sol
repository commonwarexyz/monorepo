// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.15;

import { LibBLS12381 as BLS } from "../certificate/LibBLS12381.sol";
import { LibBLS12381Multisig as Multisig } from "../certificate/LibBLS12381Multisig.sol";
import { LibBLS12381Threshold as Threshold } from "../certificate/LibBLS12381Threshold.sol";
import { LibCodec } from "../codec/LibCodec.sol";

/// @notice Verify Commonware Simplex standard certificates.
/// @dev The caller must choose the certificate kind required by its protocol. For threshold
/// certificates, it must authenticate the group key for the signed epoch. For multisignatures,
/// it must authenticate the ordered committee and identity-to-key bindings for that epoch,
/// require distinct BLS public keys, and validate every key and proof of possession at registration.
/// Payload digests are 32 bytes.
library LibSimplex {
    /// @dev The vote signing domain.
    enum Kind {
        Notarization,
        Nullification,
        Finalization
    }

    /// @notice The Simplex vote authenticated by a certificate.
    struct Subject {
        /// The vote domain required by the calling protocol.
        Kind kind;
        /// The signing epoch whose group key or registered committee the caller trusts.
        uint64 epoch;
        /// The view of the vote.
        uint64 viewNumber;
        /// The proposal's parent view, ignored for nullifications.
        uint64 parent;
        /// The proposal's payload digest, ignored for nullifications.
        bytes32 payload;
    }

    /// @notice Verify a MinSig certificate for a Simplex vote.
    /// @param signature Uncompressed G1 coordinates, as accepted by Threshold.verifyMinSig.
    /// @param publicKey The trusted G2 group key for the subject's epoch.
    /// @param namespace The application's base namespace, without a vote suffix or length prefix.
    /// @param subject The vote reconstructed from trusted context and supplied fields.
    function verifyMinSig(
        bytes calldata signature,
        BLS.G2Point memory publicKey,
        bytes memory namespace,
        Subject memory subject
    ) internal view returns (bool) {
        return Threshold.verifyMinSig(signature, publicKey, _namespace(namespace, subject.kind), _message(subject));
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
        Subject memory subject
    ) internal view returns (bool) {
        return Threshold.verifyMinPk(signature, publicKey, _namespace(namespace, subject.kind), _message(subject));
    }

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
        Subject memory subject
    ) internal view returns (bool) {
        uint256 count = publicKeys.length;
        if (count == 0) return false;
        uint256 quorum = _quorum(count);
        return Multisig.verifyMinSig(
            signature, signers, publicKeys, quorum, _namespace(namespace, subject.kind), _message(subject)
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
        Subject memory subject
    ) internal view returns (bool) {
        uint256 count = publicKeys.length;
        if (count == 0) return false;
        uint256 quorum = _quorum(count);
        return Multisig.verifyMinPk(
            signature, signers, publicKeys, quorum, _namespace(namespace, subject.kind), _message(subject)
        );
    }

    /// @notice Construct the exact signed bytes for a Simplex certificate.
    /// @dev Nullifications commit only to the epoch and view. Other votes also commit to the
    /// parent view and payload. The namespace length and integer fields use unsigned varints.
    function encodeMessage(bytes memory namespace, Subject memory subject) internal pure returns (bytes memory) {
        return BLS.encodeMessage(_namespace(namespace, subject.kind), _message(subject));
    }

    function _quorum(uint256 count) private pure returns (uint256) {
        return count - (count - 1) / 3;
    }

    function _namespace(bytes memory namespace, Kind kind) private pure returns (bytes memory) {
        bytes memory suffix = kind == Kind.Notarization
            ? bytes("_NOTARIZE")
            : kind == Kind.Nullification ? bytes("_NULLIFY") : bytes("_FINALIZE");
        return bytes.concat(namespace, suffix);
    }

    function _message(Subject memory subject) private pure returns (bytes memory) {
        bytes memory round =
            bytes.concat(LibCodec.encodeVarint(subject.epoch), LibCodec.encodeVarint(subject.viewNumber));
        if (subject.kind == Kind.Nullification) return round;
        return bytes.concat(round, LibCodec.encodeVarint(subject.parent), subject.payload);
    }
}
