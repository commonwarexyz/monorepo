// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ISignatureScheme} from "./interfaces/ISignatureScheme.sol";
import {Ed25519} from "../crypto/ed25519/Ed25519.sol";

///  Ed25519 signature scheme with individual signatures per validator
contract Ed25519Scheme is ISignatureScheme {
    uint256 private constant ED25519_PUBLIC_KEY_LENGTH = 32;
    uint256 private constant ED25519_SIGNATURE_LENGTH = 64;

    function schemeId() external pure returns (string memory) {
        return "ED25519";
    }

    function publicKeyLength() external pure returns (uint256) {
        return ED25519_PUBLIC_KEY_LENGTH;
    }

    function signatureLength() external pure returns (uint256) {
        return ED25519_SIGNATURE_LENGTH;
    }

    function verifySignature(
        bytes calldata message,
        bytes calldata publicKey,
        bytes calldata signature
    ) external pure returns (bool) {
        if (publicKey.length != ED25519_PUBLIC_KEY_LENGTH) return false;
        if (signature.length != ED25519_SIGNATURE_LENGTH) return false;

        bytes32 pk = bytes32(publicKey[0:32]);
        bytes32 r = bytes32(signature[0:32]);
        bytes32 s = bytes32(signature[32:64]);

        return Ed25519.verify(pk, r, s, message);
    }
}
