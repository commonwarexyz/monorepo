// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title SimplexVerifier
/// @notice Verifies deserialization of Simplex consensus proofs
contract SimplexVerifier {
    // Constants for proof sizes
    uint256 constant DIGEST_LENGTH = 32; // SHA256 digest length
    uint256 constant PUBLIC_KEY_LENGTH = 32; // Ed25519 public key length
    uint256 constant SIGNATURE_LENGTH = 64; // Ed25519 signature length
    
    /// @notice Verifies a notarize proof
    /// @param proof The serialized proof bytes
    /// @return (view, parent, payload, publicKey) The deserialized proof components
    function deserializeNotarize(
        bytes calldata proof
    ) public pure returns (
        uint64 view,
        uint64 parent,
        bytes32 payload,
        bytes32 publicKey
    ) {
        // Ensure proof is big enough
        require(
            proof.length == 8 + 8 + DIGEST_LENGTH + PUBLIC_KEY_LENGTH + SIGNATURE_LENGTH,
            "Invalid proof length"
        );

        // Decode proof components
        view = uint64(bytes8(proof[0:8]));
        parent = uint64(bytes8(proof[8:16]));
        payload = bytes32(proof[16:48]);
        publicKey = bytes32(proof[48:80]);
        
        // Note: Signature verification is handled separately
        return (view, parent, payload, publicKey);
    }

    /// @notice Verifies a notarization proof (aggregated)
    /// @param proof The serialized proof bytes
    /// @param maxSigners Maximum number of allowed signers
    /// @return (view, parent, payload, signerCount) The deserialized proof components
    function deserializeNotarization(
        bytes calldata proof,
        uint32 maxSigners
    ) public pure returns (
        uint64 view,
        uint64 parent, 
        bytes32 payload,
        uint32 signerCount
    ) {
        // Ensure proof prefix is big enough
        require(
            proof.length >= 8 + 8 + DIGEST_LENGTH + 4,
            "Invalid proof prefix length"
        );

        // Decode proof prefix
        view = uint64(bytes8(proof[0:8]));
        parent = uint64(bytes8(proof[8:16]));
        payload = bytes32(proof[16:48]);
        signerCount = uint32(bytes4(proof[48:52]));
        
        // Validate signer count
        require(signerCount <= maxSigners, "Too many signers");
        
        // Validate total proof length
        uint256 expectedLength = 52 + (signerCount * (PUBLIC_KEY_LENGTH + SIGNATURE_LENGTH));
        require(proof.length == expectedLength, "Invalid proof length");

        return (view, parent, payload, signerCount);
    }

    /// @notice Verifies a finalize proof
    /// @param proof The serialized proof bytes
    /// @return (view, parent, payload, publicKey) The deserialized proof components
    function deserializeFinalize(
        bytes calldata proof
    ) public pure returns (
        uint64 view,
        uint64 parent,
        bytes32 payload,
        bytes32 publicKey
    ) {
        // Reuse notarize deserialization since format is identical
        return deserializeNotarize(proof);
    }

    /// @notice Verifies a finalization proof (aggregated)
    /// @param proof The serialized proof bytes
    /// @param maxSigners Maximum number of allowed signers
    /// @return (view, parent, payload, signerCount) The deserialized proof components
    function deserializeFinalization(
        bytes calldata proof,
        uint32 maxSigners
    ) public pure returns (
        uint64 view,
        uint64 parent,
        bytes32 payload,
        uint32 signerCount
    ) {
        // Reuse notarization deserialization since format is identical
        return deserializeNotarization(proof, maxSigners);
    }

    /// @notice Verifies a conflicting notarize proof
    /// @param proof The serialized proof bytes
    /// @return (publicKey, view) The deserialized proof components
    function deserializeConflictingNotarize(
        bytes calldata proof
    ) public pure returns (
        bytes32 publicKey,
        uint64 view
    ) {
        // Ensure proof is big enough
        uint256 expectedLength = 8 + PUBLIC_KEY_LENGTH + 8 + DIGEST_LENGTH + SIGNATURE_LENGTH + 
                               8 + DIGEST_LENGTH + SIGNATURE_LENGTH;
        require(proof.length == expectedLength, "Invalid proof length");

        // Decode proof components
        view = uint64(bytes8(proof[0:8]));
        publicKey = bytes32(proof[8:40]);
        
        // Note: Additional proof components and signature verification handled separately
        return (publicKey, view);
    }

    /// @notice Verifies a conflicting finalize proof
    /// @param proof The serialized proof bytes  
    /// @return (publicKey, view) The deserialized proof components
    function deserializeConflictingFinalize(
        bytes calldata proof
    ) public pure returns (
        bytes32 publicKey,
        uint64 view
    ) {
        // Reuse conflicting notarize deserialization since format is identical
        return deserializeConflictingNotarize(proof);
    }

    /// @notice Verifies a nullify finalize proof
    /// @param proof The serialized proof bytes
    /// @return (publicKey, view) The deserialized proof components
    function deserializeNullifyFinalize(
        bytes calldata proof
    ) public pure returns (
        bytes32 publicKey,
        uint64 view
    ) {
        // Ensure proof is big enough
        uint256 expectedLength = 8 + PUBLIC_KEY_LENGTH + 8 + DIGEST_LENGTH + 
                               SIGNATURE_LENGTH + SIGNATURE_LENGTH;
        require(proof.length == expectedLength, "Invalid proof length");

        // Decode proof components
        view = uint64(bytes8(proof[0:8]));
        publicKey = bytes32(proof[8:40]);
        
        // Note: Additional proof components and signature verification handled separately
        return (publicKey, view);
    }
} 
