// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/**
 * @title KeyManager
 * @notice Abstract contract for managing keys
 */
interface IKeyManager {
    /**
     * @notice Returns the operator address associated with a given key
     * @param key The key for which to find the associated operator
     * @return The address of the operator linked to the specified key
     */
    function operatorByKey(bytes memory key) external view returns (address);

    /**
     * @notice Returns the current or previous key for a given operator
     * @dev Returns the previous key if the key was updated in the current epoch
     * @param operator The address of the operator
     * @return The key associated with the specified operator
     */
    function operatorKey(address operator) external view returns (bytes memory);

    /**
     * @notice Checks if a key was active at a specific timestamp
     * @param timestamp The timestamp to check
     * @param key The key to check
     * @return True if the key was active at the timestamp, false otherwise
     */
    function keyWasActiveAt(
        uint48 timestamp,
        bytes memory key
    ) external view returns (bool);
}
