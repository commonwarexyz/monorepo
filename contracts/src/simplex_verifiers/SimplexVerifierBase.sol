// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {CodecHelpers} from "../lib/CodecHelpers.sol";

///  Digest length constants (all 32 bytes)
library DigestLengths {
    uint256 constant SHA256 = 32;
    uint256 constant BLAKE3 = 32;
}

///  Base contract for Simplex consensus proof verification
abstract contract SimplexVerifierBase {

    error TooManySigners();
    error InvalidProofLength();
    error InvalidBitmapTrailingBits();
    error Conflicting_EpochMismatch();
    error Conflicting_ViewMismatch();
    error Conflicting_SignerMismatch();
    error Conflicting_ProposalsMustDiffer();

    ///  Format: bitmap_length (8 bytes u64) + bitmap_bytes + validates trailing bits zero
    function deserializeSignersBitmap(
        bytes calldata proof,
        uint256 offset,
        uint32 maxParticipants
    ) internal pure returns (
        uint64 bitmapLengthInBits,
        bytes calldata signersBitmap,
        uint256 newOffset
    ) {
        if (offset + 8 > proof.length) revert InvalidProofLength();
        bitmapLengthInBits = uint64(bytes8(proof[offset:offset+8]));
        offset += 8;

        if (bitmapLengthInBits > maxParticipants) revert TooManySigners();

        uint256 numBitmapBytes = (bitmapLengthInBits + 7) >> 3;

        if (offset + numBitmapBytes > proof.length) revert InvalidProofLength();
        signersBitmap = proof[offset:offset + numBitmapBytes];
        offset += numBitmapBytes;

        uint256 fullBytes = bitmapLengthInBits >> 3;
        uint256 remainder = bitmapLengthInBits & 7;
        if (remainder != 0 && numBitmapBytes > 0) {
            uint8 lastByte = uint8(signersBitmap[fullBytes]);
            uint8 allowedLower = uint8((uint256(1) << remainder) - 1);
            if ((lastByte & ~allowedLower) != 0) revert InvalidBitmapTrailingBits();
        }

        return (bitmapLengthInBits, signersBitmap, offset);
    }

    ///  Format: signer (4 bytes) + signature
    function deserializeSignerAndSignature(
        bytes calldata proof,
        uint256 offset,
        uint256 signatureLength
    ) internal pure returns (
        uint32 signer,
        bytes calldata signature,
        uint256 newOffset
    ) {
        if (offset + 4 > proof.length) revert InvalidProofLength();
        signer = uint32(bytes4(proof[offset:offset+4]));
        offset += 4;

        if (offset + signatureLength > proof.length) revert InvalidProofLength();
        signature = proof[offset:offset+signatureLength];
        offset += signatureLength;

        return (signer, signature, offset);
    }

    ///  Format: epoch (8 bytes) + view (8 bytes)
    function extractRoundBytes(bytes calldata data, uint256 offset)
        internal pure returns (bytes calldata roundBytes, uint256 newOffset)
    {
        if (offset + 16 > data.length) revert InvalidProofLength();
        return (data[offset:offset+16], offset + 16);
    }

    ///  Format: round (16 bytes) + parent (varint) + payload (digest_length bytes)
    function extractProposalBytes(bytes calldata data, uint256 offset, uint256 digestLength)
        internal pure returns (bytes calldata proposalBytes, uint256 newOffset)
    {
        uint256 startOffset = offset;
        offset += 16;
        (, offset) = CodecHelpers.decodeVarintU64(data, offset);
        if (offset + digestLength > data.length) revert InvalidProofLength();
        offset += digestLength;
        return (data[startOffset:offset], offset);
    }

    function parseRound(bytes calldata roundBytes)
        internal pure returns (uint64 epoch, uint64 viewCounter)
    {
        require(roundBytes.length == 16, "Invalid round length");
        epoch = uint64(bytes8(roundBytes[0:8]));
        viewCounter = uint64(bytes8(roundBytes[8:16]));
    }

    function parseProposalPayload(bytes calldata proposalBytes)
        internal pure returns (bytes32 payload)
    {
        require(proposalBytes.length >= 16 + 1 + 32, "Invalid proposal length");
        uint256 payloadOffset = proposalBytes.length - 32;
        payload = bytes32(proposalBytes[payloadOffset:payloadOffset+32]);
    }

    ///  Format: varint(namespace_len) + namespace + message
    function encodeSignedMessage(bytes memory namespaceWithSuffix, bytes calldata messageBytes)
        internal pure returns (bytes memory)
    {
        bytes memory lengthVarint = CodecHelpers.encodeVarintU64(uint64(namespaceWithSuffix.length));
        return abi.encodePacked(lengthVarint, namespaceWithSuffix, messageBytes);
    }

    function validateRoundsMatch(bytes calldata roundBytes1, bytes calldata roundBytes2)
        internal pure
    {
        (uint64 epoch1, uint64 viewCounter1) = parseRound(roundBytes1);
        (uint64 epoch2, uint64 viewCounter2) = parseRound(roundBytes2);
        if (epoch1 != epoch2) revert Conflicting_EpochMismatch();
        if (viewCounter1 != viewCounter2) revert Conflicting_ViewMismatch();
    }

    function validateProposalsDiffer(bytes calldata proposalBytes1, bytes calldata proposalBytes2)
        internal pure
    {
        if (keccak256(proposalBytes1) == keccak256(proposalBytes2)) {
            revert Conflicting_ProposalsMustDiffer();
        }
    }
}
