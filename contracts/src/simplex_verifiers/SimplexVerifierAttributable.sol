// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {SimplexVerifierBase} from "./SimplexVerifierBase.sol";
import {CodecHelpers} from "../lib/CodecHelpers.sol";
import {IKeyStore} from "../keystore/IKeyStore.sol";
import {ISignatureScheme} from "../signing_schemes/interfaces/ISignatureScheme.sol";

/// Verifier for attributable signature schemes with individual signatures per participant
contract SimplexVerifierAttributable is SimplexVerifierBase {
    IKeyStore public immutable KEY_STORE;
    uint256 public immutable DIGEST_LENGTH;

    /// _keyStore Keystore managing validator keys and signature scheme
    /// _digestLength Payload digest length in bytes
    constructor(
        IKeyStore _keyStore,
        uint256 _digestLength
    ) {
        KEY_STORE = _keyStore;
        DIGEST_LENGTH = _digestLength;
    }

    function scheme() public view returns (ISignatureScheme) {
        return KEY_STORE.scheme();
    }

    function signatureLength() public view returns (uint256) {
        return KEY_STORE.scheme().signatureLength();
    }

    function publicKeyLength() public view returns (uint256) {
        return KEY_STORE.scheme().publicKeyLength();
    }

    ///  Format: bitmap + signature_count (varint) + signatures
    function deserializeBitmapAndSignatures(
        bytes calldata proof,
        uint256 offset,
        uint32 maxParticipants,
        uint256 sigLength
    ) internal pure returns (
        bytes calldata signersBitmap,
        bytes[] memory signatures,
        uint256 newOffset
    ) {
        uint64 bitmapLengthInBits;
        (bitmapLengthInBits, signersBitmap, offset) =
            deserializeSignersBitmap(proof, offset, maxParticipants);

        uint64 signatureCount;
        (signatureCount, offset) = CodecHelpers.decodeVarintU64(proof, offset);

        signatures = new bytes[](signatureCount);
        for (uint64 i = 0; i < signatureCount; i++) {
            if (offset + sigLength > proof.length) revert InvalidProofLength();
            signatures[i] = proof[offset:offset + sigLength];
            offset += sigLength;
        }

        return (signersBitmap, signatures, offset);
    }

    function _verifyCertificateSignatures(
        bytes memory signedMessage,
        bytes[] memory signatures,
        bytes[] memory publicKeys
    ) internal view returns (bool) {
        if (signatures.length != publicKeys.length) return false;

        for (uint256 i = 0; i < signatures.length; i++) {
            if (!KEY_STORE.scheme().verifySignature(signedMessage, publicKeys[i], signatures[i])) {
                return false;
            }
        }

        return true;
    }

    ///  Format: proposal_bytes + signer (4 bytes) + signature
    function deserializeNotarize(bytes calldata proof)
        public view returns (
            bytes calldata proposalBytes,
            uint32 signer,
            bytes calldata signature
        )
    {
        uint256 offset;
        (proposalBytes, offset) = extractProposalBytes(proof, 0, DIGEST_LENGTH);
        (signer, signature, offset) = deserializeSignerAndSignature(proof, offset, signatureLength());
        if (offset != proof.length) revert InvalidProofLength();
        return (proposalBytes, signer, signature);
    }

    ///  Format: round_bytes (16 bytes) + signer (4 bytes) + signature
    function deserializeNullify(bytes calldata proof)
        public view returns (
            bytes calldata roundBytes,
            uint32 signer,
            bytes calldata signature
        )
    {
        uint256 offset;
        (roundBytes, offset) = extractRoundBytes(proof, 0);
        (signer, signature, offset) = deserializeSignerAndSignature(proof, offset, signatureLength());
        if (offset != proof.length) revert InvalidProofLength();
        return (roundBytes, signer, signature);
    }

    function deserializeFinalize(bytes calldata proof)
        public view returns (
            bytes calldata proposalBytes,
            uint32 signer,
            bytes calldata signature
        )
    {
        return deserializeNotarize(proof);
    }

    function verifyNotarize(
        bytes memory namespace,
        bytes calldata proof
    ) public view returns (bool) {
        (bytes calldata proposalBytes, uint32 signer, bytes calldata signature) = deserializeNotarize(proof);
        require(signer < KEY_STORE.getParticipantCount(), "Invalid signer index");
        return KEY_STORE.scheme().verifySignature(
            encodeSignedMessage(abi.encodePacked(namespace, "_NOTARIZE"), proposalBytes),
            KEY_STORE.getParticipant(signer),
            signature
        );
    }

    function verifyNullify(
        bytes memory namespace,
        bytes calldata proof
    ) public view returns (bool) {
        (bytes calldata roundBytes, uint32 signer, bytes calldata signature) = deserializeNullify(proof);
        require(signer < KEY_STORE.getParticipantCount(), "Invalid signer index");
        return KEY_STORE.scheme().verifySignature(
            encodeSignedMessage(abi.encodePacked(namespace, "_NULLIFY"), roundBytes),
            KEY_STORE.getParticipant(signer),
            signature
        );
    }

    function verifyFinalize(
        bytes memory namespace,
        bytes calldata proof
    ) public view returns (bool) {
        (bytes calldata proposalBytes, uint32 signer, bytes calldata signature) = deserializeFinalize(proof);
        require(signer < KEY_STORE.getParticipantCount(), "Invalid signer index");
        return KEY_STORE.scheme().verifySignature(
            encodeSignedMessage(abi.encodePacked(namespace, "_FINALIZE"), proposalBytes),
            KEY_STORE.getParticipant(signer),
            signature
        );
    }

    ///  Format: proposal_bytes + bitmap + signature_count (varint) + signatures
    function deserializeNotarization(bytes calldata proof, uint32 maxParticipants)
        public view returns (
            bytes calldata proposalBytes,
            bytes calldata signersBitmap,
            bytes[] memory signatures
        )
    {
        uint256 offset = 0;
        (proposalBytes, offset) = extractProposalBytes(proof, 0, DIGEST_LENGTH);
        (signersBitmap, signatures, offset) =
            deserializeBitmapAndSignatures(
                proof,
                offset,
                maxParticipants,
                signatureLength()
            );
        if (offset != proof.length) revert InvalidProofLength();
        return (proposalBytes, signersBitmap, signatures);
    }

    ///  Format: round_bytes (16 bytes) + bitmap + signature_count (varint) + signatures
    function deserializeNullification(bytes calldata proof, uint32 maxParticipants)
        public view returns (
            bytes calldata roundBytes,
            bytes calldata signersBitmap,
            bytes[] memory signatures
        )
    {
        uint256 offset = 0;
        (roundBytes, offset) = extractRoundBytes(proof, 0);
        (signersBitmap, signatures, offset) =
            deserializeBitmapAndSignatures(
                proof,
                offset,
                maxParticipants,
                signatureLength()
            );
        if (offset != proof.length) revert InvalidProofLength();
        return (roundBytes, signersBitmap, signatures);
    }

    /// Deserialize Finalization certificate (same format as Notarization)
    function deserializeFinalization(bytes calldata proof, uint32 maxParticipants)
        public view returns (
            bytes calldata proposalBytes,
            bytes calldata signersBitmap,
            bytes[] memory signatures
        )
    {
        return deserializeNotarization(proof, maxParticipants);
    }

    /// Verify certificate signatures and quorum
    function _verifyCertificate(
        bytes memory namespace,
        bytes memory suffix,
        bytes calldata messageBytes,
        bytes calldata signersBitmap,
        bytes[] memory signatures,
        uint32 quorum
    ) internal view returns (bool) {
        if (signatures.length < quorum) return false;

        bytes[] memory signerPublicKeys = new bytes[](signatures.length);
        uint256 signerIndex = 0;
        uint256 bitmapBitIndex = 0;
        uint256 participantCount = KEY_STORE.getParticipantCount();

        for (uint256 i = 0; i < participantCount && signerIndex < signatures.length; i++) {
            if (CodecHelpers.getBit(signersBitmap, bitmapBitIndex)) {
                signerPublicKeys[signerIndex] = KEY_STORE.getParticipant(i);
                signerIndex++;
            }
            bitmapBitIndex++;
        }

        return _verifyCertificateSignatures(
            encodeSignedMessage(abi.encodePacked(namespace, suffix), messageBytes),
            signatures,
            signerPublicKeys
        );
    }

    function verifyNotarization(
        bytes memory namespace,
        bytes calldata proof,
        uint32 maxParticipants,
        uint32 quorum
    ) public view returns (bool) {
        (bytes calldata proposalBytes, bytes calldata signersBitmap, bytes[] memory signatures) =
            deserializeNotarization(proof, maxParticipants);
        return _verifyCertificate(
            namespace,
            "_NOTARIZE",
            proposalBytes,
            signersBitmap,
            signatures,
            quorum
        );
    }

    function verifyNullification(
        bytes memory namespace,
        bytes calldata proof,
        uint32 maxParticipants,
        uint32 quorum
    ) public view returns (bool) {
        (bytes calldata roundBytes, bytes calldata signersBitmap, bytes[] memory signatures) =
            deserializeNullification(proof, maxParticipants);
        return _verifyCertificate(
            namespace,
            "_NULLIFY",
            roundBytes,
            signersBitmap,
            signatures,
            quorum
        );
    }

    function verifyFinalization(
        bytes memory namespace,
        bytes calldata proof,
        uint32 maxParticipants,
        uint32 quorum
    ) public view returns (bool) {
        (bytes calldata proposalBytes, bytes calldata signersBitmap, bytes[] memory signatures) =
            deserializeFinalization(proof, maxParticipants);
        return _verifyCertificate(
            namespace,
            "_FINALIZE",
            proposalBytes,
            signersBitmap,
            signatures,
            quorum
        );
    }

    /// Deserialize ConflictingNotarize fraud proof
    ///  Two notarize votes for different proposals in same round
    function deserializeConflictingNotarize(bytes calldata proof)
        public view returns (
            bytes calldata proposalBytes1,
            uint32 signer1,
            bytes calldata signature1,
            bytes calldata proposalBytes2,
            uint32 signer2,
            bytes calldata signature2
        )
    {
        uint256 offset = 0;
        (proposalBytes1, offset) = extractProposalBytes(proof, offset, DIGEST_LENGTH);
        (signer1, signature1, offset) = deserializeSignerAndSignature(proof, offset, signatureLength());
        (proposalBytes2, offset) = extractProposalBytes(proof, offset, DIGEST_LENGTH);
        (signer2, signature2, offset) = deserializeSignerAndSignature(proof, offset, signatureLength());
        if (offset != proof.length) revert InvalidProofLength();

        bytes calldata round1 = proposalBytes1[0:16];
        bytes calldata round2 = proposalBytes2[0:16];
        validateRoundsMatch(round1, round2);
        if (signer1 != signer2) revert Conflicting_SignerMismatch();
        validateProposalsDiffer(proposalBytes1, proposalBytes2);

        return (proposalBytes1, signer1, signature1, proposalBytes2, signer2, signature2);
    }

    function deserializeConflictingFinalize(bytes calldata proof)
        public view returns (
            bytes calldata proposalBytes1,
            uint32 signer1,
            bytes calldata signature1,
            bytes calldata proposalBytes2,
            uint32 signer2,
            bytes calldata signature2
        )
    {
        return deserializeConflictingNotarize(proof);
    }

    ///  Nullify and finalize votes in same round
    function deserializeNullifyFinalize(bytes calldata proof)
        public view returns (
            bytes calldata nullifyRoundBytes,
            uint32 nullifySigner,
            bytes calldata nullifySignature,
            bytes calldata finalizeProposalBytes,
            uint32 finalizeSigner,
            bytes calldata finalizeSignature
        )
    {
        uint256 offset = 0;
        (nullifyRoundBytes, offset) = extractRoundBytes(proof, offset);
        (nullifySigner, nullifySignature, offset) = deserializeSignerAndSignature(proof, offset, signatureLength());
        (finalizeProposalBytes, offset) = extractProposalBytes(proof, offset, DIGEST_LENGTH);
        (finalizeSigner, finalizeSignature, offset) = deserializeSignerAndSignature(proof, offset, signatureLength());
        if (offset != proof.length) revert InvalidProofLength();

        bytes calldata finalizeRoundBytes = finalizeProposalBytes[0:16];
        validateRoundsMatch(nullifyRoundBytes, finalizeRoundBytes);
        if (nullifySigner != finalizeSigner) revert Conflicting_SignerMismatch();

        return (nullifyRoundBytes, nullifySigner, nullifySignature, finalizeProposalBytes, finalizeSigner, finalizeSignature);
    }

    function verifyConflictingNotarize(
        bytes memory namespace,
        bytes calldata proof
    ) public view returns (bool) {
        (
            bytes calldata proposalBytes1,
            uint32 signer,
            bytes calldata signature1,
            bytes calldata proposalBytes2,
            ,
            bytes calldata signature2
        ) = deserializeConflictingNotarize(proof);

        require(signer < KEY_STORE.getParticipantCount(), "Invalid signer index");

        if (!KEY_STORE.scheme().verifySignature(
            encodeSignedMessage(abi.encodePacked(namespace, "_NOTARIZE"), proposalBytes1),
            KEY_STORE.getParticipant(signer),
            signature1
        )) {
            return false;
        }

        return KEY_STORE.scheme().verifySignature(
            encodeSignedMessage(abi.encodePacked(namespace, "_NOTARIZE"), proposalBytes2),
            KEY_STORE.getParticipant(signer),
            signature2
        );
    }

    function verifyConflictingFinalize(
        bytes memory namespace,
        bytes calldata proof
    ) public view returns (bool) {
        (
            bytes calldata proposalBytes1,
            uint32 signer,
            bytes calldata signature1,
            bytes calldata proposalBytes2,
            ,
            bytes calldata signature2
        ) = deserializeConflictingFinalize(proof);

        require(signer < KEY_STORE.getParticipantCount(), "Invalid signer index");

        if (!KEY_STORE.scheme().verifySignature(
            encodeSignedMessage(abi.encodePacked(namespace, "_FINALIZE"), proposalBytes1),
            KEY_STORE.getParticipant(signer),
            signature1
        )) {
            return false;
        }

        return KEY_STORE.scheme().verifySignature(
            encodeSignedMessage(abi.encodePacked(namespace, "_FINALIZE"), proposalBytes2),
            KEY_STORE.getParticipant(signer),
            signature2
        );
    }

    function verifyNullifyFinalize(
        bytes memory namespace,
        bytes calldata proof
    ) public view returns (bool) {
        (
            bytes calldata nullifyRoundBytes,
            uint32 signer,
            bytes calldata nullifySignature,
            bytes calldata finalizeProposalBytes,
            ,
            bytes calldata finalizeSignature
        ) = deserializeNullifyFinalize(proof);

        require(signer < KEY_STORE.getParticipantCount(), "Invalid signer index");

        if (!KEY_STORE.scheme().verifySignature(
            encodeSignedMessage(abi.encodePacked(namespace, "_NULLIFY"), nullifyRoundBytes),
            KEY_STORE.getParticipant(signer),
            nullifySignature
        )) {
            return false;
        }

        return KEY_STORE.scheme().verifySignature(
            encodeSignedMessage(abi.encodePacked(namespace, "_FINALIZE"), finalizeProposalBytes),
            KEY_STORE.getParticipant(signer),
            finalizeSignature
        );
    }
}
