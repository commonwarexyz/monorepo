// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.12;

contract MockedMiddlewareReader {
    address[] public _operators;

    function activeOperatorsAt(
        uint48 /*timestamp*/
    ) external view returns (address[] memory) {
        return _operators;
    }

    function setActiveOperators(address[] memory operators) external {
        for (uint8 i = 0; i < operators.length; i++) {
            _operators.push(operators[i]);
        }
    }
}
