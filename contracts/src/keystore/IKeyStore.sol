// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {ISignatureScheme} from "../signing_schemes/interfaces/ISignatureScheme.sol";

///  Interface for managing validator public keys
interface IKeyStore {
    event ParticipantsUpdated(uint256 count);

    function scheme() external view returns (ISignatureScheme);
    function getParticipant(uint256 index) external view returns (bytes memory);
    function getParticipantCount() external view returns (uint256);
    function setParticipants(bytes[] calldata keys) external;
}
