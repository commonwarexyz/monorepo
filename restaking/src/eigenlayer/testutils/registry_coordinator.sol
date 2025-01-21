// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.12;

contract RegistryCoordinator {
    uint8 public quorumCount;

    function setQuorumCount(uint8 value) external {
        quorumCount = value;
    }
}
