// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.12;

import {IBaseMiddlewareReader} from "../contracts/IBaseMiddlewareReader.sol";
import {StateRetriever} from "../contracts/StateRetriever.sol";

contract MockedStateRetriever {
    StateRetriever.ValidatorData[] public _validators;

    function setActiveValidators(
        StateRetriever.ValidatorData[] memory validators
    ) external {
        for (uint8 i = 0; i < validators.length; i++) {
            _validators.push(validators[i]);
        }
    }

    function getValidatorSet(
        IBaseMiddlewareReader /*reader*/
    )
        external
        view
        returns (StateRetriever.ValidatorData[] memory validatorSet)
    {
        return _validators;
    }

    function getValidatorSetAt(
        IBaseMiddlewareReader /*reader*/,
        uint48 /*timestamp*/
    )
        external
        view
        returns (StateRetriever.ValidatorData[] memory validatorSet)
    {
        return _validators;
    }
}
