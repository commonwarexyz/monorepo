// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

///  Interface for signature schemes (Ed25519, BLS, etc)
interface ISignatureScheme {
    function schemeId() external pure returns (string memory);
    function publicKeyLength() external pure returns (uint256);
    function signatureLength() external pure returns (uint256);
    function verifySignature(
        bytes calldata message,
        bytes calldata publicKey,
        bytes calldata signature
    ) external view returns (bool);
}
