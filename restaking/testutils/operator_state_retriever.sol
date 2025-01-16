// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.12;

contract OperatorStateRetriever {
    address public _registryCoordinator;

    mapping(uint8 => Operator[]) public _operators;

    struct Operator {
        address operator;
        bytes32 operatorId;
        uint96 stake;
    }

    function setRegistryCoordinator(IRegistryCoordinator value) external {
        _registryCoordinator = address(value);
    }

    function setOperators(
        uint8 quorumNumber,
        Operator[] memory operators
    ) external {
        for (uint8 i = 0; i < operators.length; i++) {
            _operators[quorumNumber].push(operators[i]);
        }
    }

    function getOperatorState(
        IRegistryCoordinator /*registryCoordinator*/,
        bytes memory quorumNumbers,
        uint32 /*blockNumber*/
    ) public view returns (Operator[][] memory) {
        Operator[][] memory operators = new Operator[][](quorumNumbers.length);
        for (uint8 i = 0; i < quorumNumbers.length; i++) {
            Operator[] memory ops = _operators[i];
            operators[i] = ops;
        }

        return operators;
    }
}

interface IRegistryCoordinator {}
