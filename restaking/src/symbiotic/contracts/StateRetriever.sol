// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {IMiddlewareReader} from "./IMiddlewareReader.sol";

contract StateRetriever {
    struct ValidatorData {
        address operator;
        bytes32 key; // Key associated with the validator
        uint256 power; // Power of the validator
    }

    function getValidatorSet(
        IMiddlewareReader reader
    ) external view returns (ValidatorData[] memory validatorSet) {
        address[] memory operators = reader.activeOperators();
        validatorSet = new ValidatorData[](operators.length); // Initialize the validator set
        uint256 len = 0; // Length counter

        for (uint256 i; i < operators.length; ++i) {
            address operator = operators[i]; // Get the operator address

            bytes32 key = abi.decode(reader.operatorKey(operator), (bytes32)); // Get the key for the operator
            if (
                key == bytes32(0) ||
                !reader.keyWasActiveAt(
                    reader.getCaptureTimestamp(),
                    abi.encode(key)
                )
            ) {
                continue; // Skip if the key is inactive
            }

            uint256 power = reader.getOperatorPower(operator); // Get the operator's power
            validatorSet[len++] = ValidatorData(operator, key, power); // Store the validator data
        }

        assembly ("memory-safe") {
            mstore(validatorSet, len) // Update the length of the array
        }
    }

    function getValidatorSetAt(
        IMiddlewareReader reader,
        uint48 timestamp
    ) external view returns (ValidatorData[] memory validatorSet) {
        address[] memory operators = reader.activeOperatorsAt(timestamp);
        validatorSet = new ValidatorData[](operators.length); // Initialize the validator set
        uint256 len = 0; // Length counter

        for (uint256 i; i < operators.length; ++i) {
            address operator = operators[i]; // Get the operator address

            bytes32 key = abi.decode(reader.operatorKey(operator), (bytes32)); // Get the key for the operator
            if (
                key == bytes32(0) ||
                !reader.keyWasActiveAt(timestamp, abi.encode(key))
            ) {
                continue; // Skip if the key is inactive
            }

            uint256 power = reader.getOperatorPowerAt(timestamp, operator); // Get the operator's power
            validatorSet[len++] = ValidatorData(operator, key, power); // Store the validator data
        }

        assembly ("memory-safe") {
            mstore(validatorSet, len) // Update the length of the array
        }
    }
}
