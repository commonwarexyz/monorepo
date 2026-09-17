// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.15;

import { LibBLS12381Threshold as Certificate } from "../certificate/LibBLS12381Threshold.sol";
import { LibCodec } from "../codec/LibCodec.sol";

/// @notice Verify Commonware Simplex standard threshold certificates.
/// @dev The caller must authenticate the group key for the signed epoch and choose the
/// certificate kind required by its protocol. Payload digests are 32 bytes.
library LibSimplex {
    /// @dev The signing domain for the recovered vote signature.
    enum Kind {
        Notarization,
        Nullification,
        Finalization
    }

    /// @notice The Simplex vote authenticated by a certificate.
    struct Subject {
        /// The vote domain required by the calling protocol.
        Kind kind;
        /// The signing epoch whose group key the caller trusts.
        uint64 epoch;
        /// The view of the vote.
        uint64 viewNumber;
        /// The proposal's parent view, ignored for nullifications.
        uint64 parent;
        /// The proposal's payload digest, ignored for nullifications.
        bytes32 payload;
    }

    /// @notice Verify a MinSig certificate for a Simplex vote.
    /// @param signature Uncompressed G1 coordinates, as accepted by Certificate.verifyMinSig.
    /// @param publicKey The trusted G2 group key for the subject's epoch.
    /// @param namespace The application's base namespace, without a vote suffix or length prefix.
    /// @param subject The vote reconstructed from trusted context and supplied fields.
    function verifyMinSig(
        bytes calldata signature,
        Certificate.G2Point memory publicKey,
        bytes memory namespace,
        Subject memory subject
    ) internal view returns (bool) {
        return Certificate.verifyMinSig(signature, publicKey, _namespace(namespace, subject.kind), _message(subject));
    }

    /// @notice Verify a MinPk certificate for a Simplex vote.
    /// @param signature Uncompressed G2 coordinates, as accepted by Certificate.verifyMinPk.
    /// @param publicKey The trusted G1 group key for the subject's epoch.
    /// @param namespace The application's base namespace, without a vote suffix or length prefix.
    /// @param subject The vote reconstructed from trusted context and supplied fields.
    function verifyMinPk(
        bytes calldata signature,
        Certificate.G1Point memory publicKey,
        bytes memory namespace,
        Subject memory subject
    ) internal view returns (bool) {
        return Certificate.verifyMinPk(signature, publicKey, _namespace(namespace, subject.kind), _message(subject));
    }

    /// @notice Construct the exact signed bytes for a Simplex threshold certificate.
    /// @dev Nullifications commit only to the epoch and view. Other votes also commit to the
    /// parent view and payload. The namespace length and integer fields use unsigned varints.
    function encodeMessage(bytes memory namespace, Subject memory subject) internal pure returns (bytes memory) {
        return Certificate.encodeMessage(_namespace(namespace, subject.kind), _message(subject));
    }

    function _namespace(bytes memory namespace, Kind kind) private pure returns (bytes memory) {
        bytes memory suffix = kind == Kind.Notarization
            ? bytes("_NOTARIZE")
            : kind == Kind.Nullification ? bytes("_NULLIFY") : bytes("_FINALIZE");
        return bytes.concat(namespace, suffix);
    }

    function _message(Subject memory subject) private pure returns (bytes memory) {
        bytes memory round = bytes.concat(LibCodec.encodeU64(subject.epoch), LibCodec.encodeU64(subject.viewNumber));
        if (subject.kind == Kind.Nullification) return round;
        return bytes.concat(round, LibCodec.encodeU64(subject.parent), subject.payload);
    }
}
