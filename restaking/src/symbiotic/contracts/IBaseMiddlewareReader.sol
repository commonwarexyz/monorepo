// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

interface IBaseMiddlewareReader {
    function getCaptureTimestamp() external view returns (uint48 timestamp);

    function stakeToPower(address vault, uint256 stake) external view returns (uint256 power);

    function keyWasActiveAt(uint48 timestamp, bytes memory key) external view returns (bool);

    function operatorKey(
        address operator
    ) external view returns (bytes memory);

    function operatorByKey(
        bytes memory key
    ) external view returns (address);

    function NETWORK() external view returns (address);

    function SLASHING_WINDOW() external view returns (uint48);

    function VAULT_REGISTRY() external view returns (address);

    function OPERATOR_REGISTRY() external view returns (address);

    function OPERATOR_NET_OPTIN() external view returns (address);

    function operatorsLength() external view returns (uint256);

    function operatorWithTimesAt(
        uint256 pos
    ) external view returns (address, uint48, uint48);

    function activeOperators() external view returns (address[] memory);

    function activeOperatorsAt(
        uint48 timestamp
    ) external view returns (address[] memory);

    function operatorWasActiveAt(uint48 timestamp, address operator) external view returns (bool);

    function isOperatorRegistered(
        address operator
    ) external view returns (bool);

    function subnetworksLength() external view returns (uint256);

    function subnetworkWithTimesAt(
        uint256 pos
    ) external view returns (uint160, uint48, uint48);

    function activeSubnetworks() external view returns (uint160[] memory);

    function activeSubnetworksAt(
        uint48 timestamp
    ) external view returns (uint160[] memory);

    function subnetworkWasActiveAt(uint48 timestamp, uint96 subnetwork) external view returns (bool);

    function sharedVaultsLength() external view returns (uint256);

    function sharedVaultWithTimesAt(
        uint256 pos
    ) external view returns (address, uint48, uint48);

    function activeSharedVaults() external view returns (address[] memory);

    function activeSharedVaultsAt(
        uint48 timestamp
    ) external view returns (address[] memory);

    function operatorVaultsLength(
        address operator
    ) external view returns (uint256);

    function operatorVaultWithTimesAt(address operator, uint256 pos) external view returns (address, uint48, uint48);

    function activeOperatorVaults(
        address operator
    ) external view returns (address[] memory);

    function activeOperatorVaultsAt(uint48 timestamp, address operator) external view returns (address[] memory);

    function activeVaults() external view returns (address[] memory);

    function activeVaultsAt(
        uint48 timestamp
    ) external view returns (address[] memory);

    function activeVaults(
        address operator
    ) external view returns (address[] memory);

    function activeVaultsAt(uint48 timestamp, address operator) external view returns (address[] memory);

    function vaultWasActiveAt(uint48 timestamp, address operator, address vault) external view returns (bool);

    function sharedVaultWasActiveAt(uint48 timestamp, address vault) external view returns (bool);

    function operatorVaultWasActiveAt(uint48 timestamp, address operator, address vault) external view returns (bool);

    function getOperatorPower(address operator, address vault, uint96 subnetwork) external view returns (uint256);

    function getOperatorPowerAt(
        uint48 timestamp,
        address operator,
        address vault,
        uint96 subnetwork
    ) external view returns (uint256);

    function getOperatorPower(
        address operator
    ) external view returns (uint256);

    function getOperatorPowerAt(uint48 timestamp, address operator) external view returns (uint256);

    function getOperatorPower(
        address operator,
        address[] memory vaults,
        uint160[] memory subnetworks
    ) external view returns (uint256);

    function getOperatorPowerAt(
        uint48 timestamp,
        address operator,
        address[] memory vaults,
        uint160[] memory subnetworks
    ) external view returns (uint256);

    function totalPower(
        address[] memory operators
    ) external view returns (uint256);
}
