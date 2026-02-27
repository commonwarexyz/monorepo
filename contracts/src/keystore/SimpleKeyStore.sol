// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {IKeyStore} from "./IKeyStore.sol";
import {ISignatureScheme} from "../signing_schemes/interfaces/ISignatureScheme.sol";

///  Simple key storage for a single validator set (no epoch rotation)
contract SimpleKeyStore is IKeyStore {
    ISignatureScheme public immutable SCHEME;
    bytes[] public participants;

    /// _scheme Signature scheme defining key format and length
    constructor(ISignatureScheme _scheme) {
        SCHEME = _scheme;
    }

    function scheme() external view returns (ISignatureScheme) {
        return SCHEME;
    }

    function setParticipants(bytes[] calldata keys) external {
        uint256 expectedLength = SCHEME.publicKeyLength();

        for (uint256 i = 0; i < keys.length; i++) {
            require(keys[i].length == expectedLength, "Invalid key length for scheme");
        }

        delete participants;

        for (uint256 i = 0; i < keys.length; i++) {
            participants.push(keys[i]);
        }

        emit ParticipantsUpdated(keys.length);
    }

    function getParticipant(uint256 index) external view returns (bytes memory) {
        require(index < participants.length, "Invalid participant index");
        return participants[index];
    }

    function getParticipantCount() external view returns (uint256) {
        return participants.length;
    }
}
