// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../contracts/SimplexVerifier.sol";

contract SimplexVerifierTest is Test {
    SimplexVerifier verifier;

    function setUp() public {
        verifier = new SimplexVerifier();
    }

    function testDeserializeNotarize() public {
        // Create test proof
        bytes memory proof = new bytes(144); // 8 + 8 + 32 + 32 + 64
        
        // Set view and parent
        bytes8 view = bytes8(uint64(123));
        bytes8 parent = bytes8(uint64(456));
        for(uint i = 0; i < 8; i++) {
            proof[i] = view[i];
            proof[i+8] = parent[i];
        }

        // Set payload
        bytes32 payload = bytes32(uint256(789));
        for(uint i = 0; i < 32; i++) {
            proof[i+16] = payload[i];
        }

        // Set public key
        bytes32 publicKey = bytes32(uint256(101112));
        for(uint i = 0; i < 32; i++) {
            proof[i+48] = publicKey[i];
        }

        // Call function
        (uint64 resultView, uint64 resultParent, bytes32 resultPayload, bytes32 resultPublicKey) = 
            verifier.deserializeNotarize(proof);

        // Verify results
        assertEq(resultView, 123);
        assertEq(resultParent, 456);
        assertEq(uint256(resultPayload), 789);
        assertEq(uint256(resultPublicKey), 101112);
    }

    function testDeserializeNotarization() public {
        // Create test proof with 2 signers
        uint32 signerCount = 2;
        bytes memory proof = new bytes(52 + (signerCount * 96)); // 8 + 8 + 32 + 4 + (2 * (32 + 64))
        
        // Set view and parent
        bytes8 view = bytes8(uint64(123));
        bytes8 parent = bytes8(uint64(456));
        for(uint i = 0; i < 8; i++) {
            proof[i] = view[i];
            proof[i+8] = parent[i];
        }

        // Set payload
        bytes32 payload = bytes32(uint256(789));
        for(uint i = 0; i < 32; i++) {
            proof[i+16] = payload[i];
        }

        // Set signer count
        bytes4 count = bytes4(uint32(signerCount));
        for(uint i = 0; i < 4; i++) {
            proof[i+48] = count[i];
        }

        // Call function
        (uint64 resultView, uint64 resultParent, bytes32 resultPayload, uint32 resultSignerCount) = 
            verifier.deserializeNotarization(proof, 5);

        // Verify results
        assertEq(resultView, 123);
        assertEq(resultParent, 456);
        assertEq(uint256(resultPayload), 789);
        assertEq(resultSignerCount, 2);
    }

    function testDeserializeConflictingNotarize() public {
        // Create test proof
        bytes memory proof = new bytes(216); // 8 + 32 + 8 + 32 + 64 + 8 + 32 + 64
        
        // Set view
        bytes8 view = bytes8(uint64(123));
        for(uint i = 0; i < 8; i++) {
            proof[i] = view[i];
        }

        // Set public key
        bytes32 publicKey = bytes32(uint256(456));
        for(uint i = 0; i < 32; i++) {
            proof[i+8] = publicKey[i];
        }

        // Call function
        (bytes32 resultPublicKey, uint64 resultView) = verifier.deserializeConflictingNotarize(proof);

        // Verify results
        assertEq(uint256(resultPublicKey), 456);
        assertEq(resultView, 123);
    }

    function testDeserializeNullifyFinalize() public {
        // Create test proof
        bytes memory proof = new bytes(176); // 8 + 32 + 8 + 32 + 64 + 64
        
        // Set view
        bytes8 view = bytes8(uint64(123));
        for(uint i = 0; i < 8; i++) {
            proof[i] = view[i];
        }

        // Set public key
        bytes32 publicKey = bytes32(uint256(456));
        for(uint i = 0; i < 32; i++) {
            proof[i+8] = publicKey[i];
        }

        // Call function
        (bytes32 resultPublicKey, uint64 resultView) = verifier.deserializeNullifyFinalize(proof);

        // Verify results
        assertEq(uint256(resultPublicKey), 456);
        assertEq(resultView, 123);
    }

    function testFailDeserializeNotarizeInvalidLength() public {
        bytes memory proof = new bytes(143); // Invalid length
        verifier.deserializeNotarize(proof);
    }

    function testFailDeserializeNotarizationTooManySigners() public {
        bytes memory proof = new bytes(52);
        bytes4 count = bytes4(uint32(6)); // More than max (5)
        for(uint i = 0; i < 4; i++) {
            proof[i+48] = count[i];
        }
        verifier.deserializeNotarization(proof, 5);
    }
} 
