// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.15;

import { Test } from "forge-std/Test.sol";
import { LibBajillion } from "../src/bajillion/LibBajillion.sol";
import { LibQMDB } from "../src/qmdb/LibQMDB.sol";

contract BajillionHarness {
    /// @dev Exercise the library through its calldata proof path.
    function verify(
        bytes32 root,
        bytes32 account,
        uint64 balance,
        bytes32 nextKey,
        LibQMDB.Proof calldata proof,
        address hasher
    ) external view returns (bool) {
        return LibBajillion.verifyBalance(root, account, balance, nextKey, proof, hasher);
    }
}

contract LibBajillionTest is Test {
    BajillionHarness internal harness = new BajillionHarness();

    /// @dev Fixed digests commit a 73-byte update with a non-palindromic big-endian balance.
    function test_BalanceEncoding() public view {
        LibQMDB.Proof memory p;
        p.leaves = 1;
        p.chunk = bytes32(uint256(1) << 248);
        p.opsRoot = 0xf51141b3943e005f9684de4988ce441c257285123c4bda9b4e1e6030f623cf19;
        p.partialDigest = 0x48078cfed56339ea54962e72c37c7f588fc4f8e5bc173827ba75cb10a63a96a5;
        assertTrue(
            harness.verify(
                0x420bcb7d3aabfac71a91fc652526f6225353808fb5f6fef89f57522930a66fcd,
                0x1111111111111111111111111111111111111111111111111111111111111111,
                0x0123456789abcdef,
                0x2222222222222222222222222222222222222222222222222222222222222222,
                p,
                address(0)
            )
        );
    }

    /// @dev Account, balance and successor all belong to the authenticated update.
    function testFuzz_Balance(bytes32 account, uint64 balance, bytes32 nextKey, bool sha) public view {
        if (balance == 0) balance = 1;
        (bytes32 root, LibQMDB.Proof memory p) = _proof(account, balance, nextKey, sha);
        address hasher = sha ? address(2) : address(0);
        assertTrue(harness.verify(root, account, balance, nextKey, p, hasher));
        assertFalse(harness.verify(root, account ^ bytes32(uint256(1)), balance, nextKey, p, hasher));
        assertFalse(harness.verify(root, account, balance ^ 1, nextKey, p, hasher));
        assertFalse(harness.verify(root, account, balance, nextKey ^ bytes32(uint256(1)), p, hasher));
        assertFalse(harness.verify(root ^ bytes32(uint256(1)), account, balance, nextKey, p, hasher));
    }

    /// @dev A single live account can be its own cyclic successor.
    function test_SingleAccountRingAndMaximumBalance() public view {
        bytes32 account = bytes32(uint256(1));
        (bytes32 root, LibQMDB.Proof memory p) = _proof(account, type(uint64).max, account, true);
        assertTrue(harness.verify(root, account, type(uint64).max, account, p, address(2)));
    }

    /// @dev Zero is not a live Bajillion balance even if an update committing it is supplied.
    function test_ZeroBalance() public view {
        (bytes32 root, LibQMDB.Proof memory p) = _proof(bytes32(uint256(1)), 0, bytes32(uint256(1)), false);
        assertFalse(harness.verify(root, bytes32(uint256(1)), 0, bytes32(uint256(1)), p, address(0)));
    }

    /// @dev Measure the wrapper and shared verifier together with each supported built-in hash.
    function testGas_SingleAccount() public {
        for (uint256 i; i < 2; ++i) {
            bool sha = i != 0;
            (bytes32 root, LibQMDB.Proof memory p) = _proof(bytes32(uint256(1)), 50, bytes32(uint256(1)), sha);
            assertTrue(
                harness.verify(root, bytes32(uint256(1)), 50, bytes32(uint256(1)), p, sha ? address(2) : address(0))
            );
            emit log_named_uint(sha ? "Bajillion SHA256" : "Bajillion Keccak256", vm.lastFrameGas().gasTotalUsed);
        }
    }

    /// @dev Build a one-operation current root independently from the verifier.
    function _proof(bytes32 account, uint64 balance, bytes32 nextKey, bool sha)
        private
        pure
        returns (bytes32 root, LibQMDB.Proof memory p)
    {
        bytes32 leaf = _hash(abi.encodePacked(uint64(0), bytes1(0xd2), account, balance, nextKey), sha);
        p.leaves = 1;
        p.chunk = bytes32(uint256(1) << 248);
        p.opsRoot = _hash(abi.encodePacked(uint64(1), leaf), sha);
        p.partialDigest = _hash(abi.encodePacked(p.chunk), sha);
        root = _hash(abi.encodePacked(p.opsRoot, p.opsRoot, uint64(1), p.partialDigest), sha);
    }

    /// @dev Use Solidity's hash implementations as the test oracle.
    function _hash(bytes memory input, bool sha) private pure returns (bytes32) {
        return sha ? sha256(input) : keccak256(input);
    }
}
