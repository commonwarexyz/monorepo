// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.15;

import { Test } from "forge-std/Test.sol";
import { LibBLS12381 as BLS } from "../src/certificate/LibBLS12381.sol";
import { LibBLS12381Multisig as Certificate } from "../src/certificate/LibBLS12381Multisig.sol";

contract MultisigHarness is Test {
    function verify(
        bool minSig,
        bytes calldata signature,
        bytes calldata signers,
        bytes memory keys,
        uint256 quorum,
        bytes memory namespace,
        bytes memory message
    ) external view returns (bool) {
        uint256 size = minSig ? 256 : 128;
        if (keys.length % size != 0) return false;
        bytes memory encoded = bytes.concat(abi.encode(uint256(32), keys.length / size), keys);
        return minSig
            ? Certificate.verifyMinSig(
                signature, signers, abi.decode(encoded, (BLS.G2Point[])), quorum, namespace, message
            )
            : Certificate.verifyMinPk(
                signature, signers, abi.decode(encoded, (BLS.G1Point[])), quorum, namespace, message
            );
    }

    function checkedVerify(
        bool minSig,
        bytes calldata signature,
        bytes calldata signers,
        bytes memory keys,
        uint256 quorum,
        bytes memory namespace,
        bytes memory message
    ) external view {
        bytes32 inputs = keccak256(abi.encode(namespace, message));
        uint256 beforeFree;
        uint256 afterFree;
        uint256 zero;
        if (minSig) {
            BLS.G2Point[] memory publicKeys =
                abi.decode(bytes.concat(abi.encode(uint256(32), keys.length / 256), keys), (BLS.G2Point[]));
            bytes32 beforeKeys = keccak256(abi.encode(publicKeys));
            assembly ("memory-safe") { beforeFree := mload(0x40) }
            assertTrue(Certificate.verifyMinSig(signature, signers, publicKeys, quorum, namespace, message));
            assertEq(keccak256(abi.encode(publicKeys)), beforeKeys, "committee changed");
        } else {
            BLS.G1Point[] memory publicKeys =
                abi.decode(bytes.concat(abi.encode(uint256(32), keys.length / 128), keys), (BLS.G1Point[]));
            bytes32 beforeKeys = keccak256(abi.encode(publicKeys));
            assembly ("memory-safe") { beforeFree := mload(0x40) }
            assertTrue(Certificate.verifyMinPk(signature, signers, publicKeys, quorum, namespace, message));
            assertEq(keccak256(abi.encode(publicKeys)), beforeKeys, "committee changed");
        }
        assembly ("memory-safe") {
            afterFree := mload(0x40)
            zero := mload(0x60)
        }
        assertGe(afterFree, beforeFree, "free pointer moved backwards");
        assertEq(afterFree & 31, 0, "unaligned free pointer");
        assertEq(zero, 0, "dirty zero slot");
        assertEq(keccak256(abi.encode(namespace, message)), inputs, "message changed");
        bytes memory fresh = new bytes(257);
        for (uint256 i; i < fresh.length; ++i) {
            assertEq(fresh[i], bytes1(0), "dirty fresh allocation");
        }
    }
}

contract LibBLS12381MultisigTest is Test {
    struct Case {
        bytes signature;
        bytes keys;
        bytes signers;
        bytes message;
    }

    MultisigHarness internal harness;

    function setUp() public {
        harness = new MultisigHarness();
    }

    function test_EmptyCommittee() public view {
        assertFalse(harness.verify(true, new bytes(96), "", "", 0, "", ""));
        assertFalse(harness.verify(false, new bytes(192), "", "", 1, "", ""));
    }

    function testFuzz_DifferentialCertificate(
        bool minSig,
        bytes memory namespace,
        bytes memory message,
        uint8 size,
        uint64 seed
    ) public {
        uint256 participants = uint256(size) % 65 + 1;
        uint256 quorum = participants - (participants - 1) / 3;
        bytes memory signers = _signers(participants, quorum, uint256(seed) % participants);
        Case memory c = _generate(minSig, namespace, message, participants, signers, seed);
        assertEq(c.message, BLS.encodeMessage(namespace, message), "signing transcript mismatch");
        _compare(minSig, namespace, message, c, quorum, true);
        _compare(minSig, bytes.concat(namespace, hex"00"), message, c, quorum, false);
        _compare(minSig, namespace, bytes.concat(message, hex"00"), c, quorum, false);
        harness.checkedVerify(minSig, c.signature, c.signers, c.keys, quorum, namespace, message);
    }

    function test_DifferentialBitmapBoundaries() public {
        uint256[12] memory sizes = [uint256(1), 2, 7, 8, 9, 16, 17, 64, 65, 255, 256, 257];
        for (uint256 family; family != 2; ++family) {
            bool minSig = family == 0;
            for (uint256 i; i < sizes.length; ++i) {
                uint256 participants = sizes[i];
                bytes memory signers = _signers(participants, 1, participants - 1);
                Case memory c = _generate(minSig, "bitmap", "message", participants, signers, 9);
                assertTrue(_verify(minSig, "bitmap", "message", c, 1));
                assertFalse(_verify(minSig, "bitmap", "message", c, 2));
                c.signers = new bytes(signers.length);
                assertFalse(_verify(minSig, "bitmap", "message", c, 1));
            }
        }
    }

    function test_DifferentialIdentityAggregates() public {
        for (uint256 family; family != 2; ++family) {
            bool minSig = family == 0;
            Case memory c = _generate(minSig, "identity", "message", 2, hex"02", 9);
            uint256 size = minSig ? 256 : 128;
            bytes memory first = new bytes(size);
            bytes memory second = new bytes(size);
            for (uint256 i; i < size; ++i) {
                first[i] = c.keys[i];
                second[i] = c.keys[size + i];
            }

            // Multiplication by r - 1 negates the first key while preserving subgroup membership.
            (bool ok, bytes memory negative) = (minSig ? address(0x0e) : address(0x0c))
            .staticcall(
                abi.encodePacked(first, uint256(0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000))
            );
            assertTrue(ok);
            assertEq(negative.length, size);
            c.keys = bytes.concat(first, negative, second);
            c.signers = hex"07";
            _compare(minSig, "identity", "message", c, 3, true);
            harness.checkedVerify(minSig, c.signature, c.signers, c.keys, 3, "identity", "message");

            c.signers = hex"03";
            _compare(minSig, "identity", "message", c, 2, false);
            c.signature = new bytes(c.signature.length);
            _compare(minSig, "identity", "message", c, 2, false);
        }
    }

    function test_DifferentialQuorums() public {
        for (uint256 family; family != 2; ++family) {
            bool minSig = family == 0;
            for (uint256 count = 1; count <= 4; ++count) {
                Case memory c = _generate(minSig, "quorum", "message", 4, _signers(4, count, 1), 9);
                _compare(minSig, "quorum", "message", c, count, true);
                _compare(minSig, "quorum", "message", c, 1, true);
                _compare(minSig, "quorum", "message", c, count + 1, false);
                _compare(minSig, "quorum", "message", c, 0, false);
                _compare(minSig, "quorum", "message", c, type(uint256).max, false);
            }
        }
    }

    function test_DifferentialSignerMutations() public {
        for (uint256 family; family != 2; ++family) {
            bool minSig = family == 0;
            Case memory c = _generate(minSig, "signers", "message", 9, hex"8101", 9);
            _compare(minSig, "signers", "message", c, 3, true);
            bytes memory signers = c.signers;
            c.signers = hex"8201";
            _compare(minSig, "signers", "message", c, 3, false);
            c.signers = hex"0101";
            _compare(minSig, "signers", "message", c, 2, false);
            c.signers = hex"8301";
            _compare(minSig, "signers", "message", c, 3, false);
            c.signers = hex"8103";
            _compare(minSig, "signers", "message", c, 3, false);
            c.signers = hex"81";
            _compare(minSig, "signers", "message", c, 3, false);
            c.signers = hex"810100";
            _compare(minSig, "signers", "message", c, 3, false);
            c.signers = "";
            _compare(minSig, "signers", "message", c, 3, false);
            c.signers = signers;

            uint256 size = minSig ? 256 : 128;
            _swap(c.keys, size, 0, 1);
            _compare(minSig, "signers", "message", c, 3, false);
            _swap(c.keys, size, 0, 1);
            _swap(c.keys, size, 1, 2);
            _compare(minSig, "signers", "message", c, 3, true);
        }
    }

    function test_DifferentialMalformedPoints() public {
        for (uint256 family; family != 2; ++family) {
            bool minSig = family == 0;
            Case memory c = _generate(minSig, "points", "message", 4, hex"07", 9);
            bytes memory signature = c.signature;
            c.signature = new bytes(signature.length - 1);
            _compare(minSig, "points", "message", c, 3, false);
            c.signature = bytes.concat(signature, hex"00");
            _compare(minSig, "points", "message", c, 3, false);
            c.signature = new bytes(signature.length);
            _compare(minSig, "points", "message", c, 3, false);
            c.signature = bytes.concat(signature);
            c.signature[0] = 0xff;
            _compare(minSig, "points", "message", c, 3, false);
            c.signature = signature;
            bytes memory keys = c.keys;
            c.keys = bytes.concat(keys);
            c.keys[0] = 0xff;
            _compare(minSig, "points", "message", c, 3, false);
            c.keys = bytes.concat(keys);
            uint256 size = minSig ? 256 : 128;
            for (uint256 i; i < size; ++i) {
                c.keys[i] = 0;
            }
            _compare(minSig, "points", "message", c, 3, false);
            c.keys = bytes.concat(keys, hex"00");
            _compare(minSig, "points", "message", c, 3, false);
            c.keys = keys;
            _compare(minSig, "points", "message", c, 3, true);
        }
    }

    function test_DifferentialGas() public {
        uint256[3] memory sizes = [uint256(4), 16, 64];
        for (uint256 family; family != 2; ++family) {
            bool minSig = family == 0;
            for (uint256 i; i < sizes.length; ++i) {
                uint256 participants = sizes[i];
                uint256[2] memory quorums = [uint256(1), participants - (participants - 1) / 3];
                for (uint256 j; j < quorums.length; ++j) {
                    uint256 quorum = quorums[j];
                    Case memory c = _generate(
                        minSig,
                        "certificate",
                        abi.encode(uint256(7)),
                        participants,
                        _signers(participants, quorum, 0),
                        9
                    );
                    assertTrue(
                        harness.verify(
                            minSig, c.signature, c.signers, c.keys, quorum, "certificate", abi.encode(uint256(7))
                        )
                    );
                    vm.snapshotGasLastFrame(
                        "BLS12381Multisig",
                        string.concat(
                            minSig ? "minsig" : "minpk",
                            "_participants=",
                            vm.toString(participants),
                            "_signers=",
                            vm.toString(quorum)
                        )
                    );
                }
            }
        }
    }

    function _signers(uint256 participants, uint256 count, uint256 start) internal pure returns (bytes memory bitmap) {
        bitmap = new bytes((participants + 7) / 8);
        for (uint256 i; i < count; ++i) {
            uint256 index = (start + i) % participants;
            bitmap[index / 8] |= bytes1(uint8(1 << (index % 8)));
        }
    }

    function _swap(bytes memory keys, uint256 size, uint256 a, uint256 b) internal pure {
        for (uint256 i; i < size; ++i) {
            (keys[a * size + i], keys[b * size + i]) = (keys[b * size + i], keys[a * size + i]);
        }
    }

    function _generate(
        bool minSig,
        bytes memory namespace,
        bytes memory message,
        uint256 participants,
        bytes memory signers,
        uint64 seed
    ) internal returns (Case memory c) {
        string[] memory args = new string[](10);
        args[0] = _binary();
        args[1] = "certificate";
        args[2] = "multisig";
        args[3] = "generate";
        args[4] = minSig ? "minsig" : "minpk";
        args[5] = vm.toString(namespace);
        args[6] = vm.toString(message);
        args[7] = vm.toString(participants);
        args[8] = vm.toString(signers);
        args[9] = vm.toString(uint256(seed));
        (c.signature, c.keys, c.signers, c.message) = abi.decode(vm.ffi(args), (bytes, bytes, bytes, bytes));
    }

    function _compare(
        bool minSig,
        bytes memory namespace,
        bytes memory message,
        Case memory c,
        uint256 quorum,
        bool expected
    ) internal {
        string[] memory args = new string[](11);
        args[0] = _binary();
        args[1] = "certificate";
        args[2] = "multisig";
        args[3] = "check";
        args[4] = minSig ? "minsig" : "minpk";
        args[5] = vm.toString(c.keys);
        args[6] = vm.toString(c.signers);
        args[7] = vm.toString(quorum);
        args[8] = vm.toString(namespace);
        args[9] = vm.toString(message);
        args[10] = vm.toString(c.signature);
        assertEq(abi.decode(vm.ffi(args), (bool)), expected, "Commonware result");
        assertEq(_verify(minSig, namespace, message, c, quorum), expected, "Solidity result");
    }

    function _verify(bool minSig, bytes memory namespace, bytes memory message, Case memory c, uint256 quorum)
        internal
        view
        returns (bool)
    {
        return harness.verify{ gas: 2_000_000 }(minSig, c.signature, c.signers, c.keys, quorum, namespace, message);
    }

    function _binary() internal view returns (string memory) {
        return string.concat(vm.projectRoot(), "/../target/release/commonware-sol-fuzz");
    }
}
