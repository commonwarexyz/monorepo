// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {ISignatureScheme} from "./ISignatureScheme.sol";

/// Interface for multisignature schemes with key aggregation support
/// Bitmaps are used to indicate which participants signed a message.
interface IMultisigScheme is ISignatureScheme {
    function aggregatePublicKeys(
        bytes calldata publicKeyBytes,
        bytes calldata bitmap,
        uint256 numParticipants
    ) external pure returns (bytes memory aggregatedKey);
}