// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.15;

import { LibMerkle } from "../src/merkle/LibMerkle.sol";
import { QMDBTest, Encoding } from "./Common.t.sol";
import { LibQMDBCommon } from "../src/qmdb/LibQMDBCommon.sol";
import { LibQMDBKeylessMMB } from "../src/qmdb/LibQMDBKeylessMMB.sol";
import { LibQMDBKeylessMMR } from "../src/qmdb/LibQMDBKeylessMMR.sol";

struct KeylessCase {
    bytes32 root;
    bytes operation;
    LibQMDBCommon.Proof proof;
}

abstract contract LibQMDBKeylessTest is QMDBTest {
    enum KeylessOperation {
        Append,
        Commit,
        CommitMetadata
    }

    /// @dev Caller allocations and reusable scratch survive successful and rejected proofs.
    function checked(KeylessCase calldata c) external view returns (bool valid) {
        bytes memory operation = c.operation;
        bytes memory guard = abi.encode(c);
        bytes32 beforeInputs = keccak256(abi.encode(operation, guard));
        for (uint256 repeat; repeat < 2; ++repeat) {
            uint256 beforePointer;
            uint256 afterPointer;
            uint256 zero;
            assembly ("memory-safe") {
                beforePointer := mload(0x40)
                for { let p := beforePointer } lt(p, add(beforePointer, 0x2000)) { p := add(p, 32) } {
                    mstore(p, not(0))
                }
            }
            bool result = _family() == LibMerkle.Family.MMB
                ? LibQMDBKeylessMMB.verify(c.root, operation, c.proof, _hasher())
                : LibQMDBKeylessMMR.verify(c.root, operation, c.proof, _hasher());
            assembly ("memory-safe") {
                afterPointer := mload(0x40)
                zero := mload(0x60)
            }
            assertGe(afterPointer, beforePointer, "free memory pointer moved backwards");
            assertEq(afterPointer & 31, 0, "unaligned free memory pointer");
            assertEq(zero, 0, "zero slot changed");
            if (repeat != 0) assertEq(result, valid, "repeated result changed");
            valid = result;
            bytes memory fresh = new bytes(97);
            for (uint256 i; i < fresh.length; ++i) {
                assertEq(uint8(fresh[i]), 0, "new allocation is dirty");
                fresh[i] = bytes1(uint8(i));
            }
            assertEq(keccak256(abi.encode(operation, guard)), beforeInputs, "caller memory changed");
        }
    }

    /// @dev One or two leaves determine their positioned preimages without a geometry implementation.
    function smallCase(bytes memory operation, bool second) internal pure returns (KeylessCase memory c) {
        c.operation = operation;
        c.proof.leaves = second ? 2 : 1;
        c.proof.location = second ? 1 : 0;
        bytes32 folded = _hash(abi.encodePacked(uint64(c.proof.location), operation));
        c.proof.digests = new bytes32[](second ? 1 : 0);
        if (second) {
            c.proof.digests[0] = _hash(abi.encodePacked(uint64(0), hex"000000"));
            folded = _hash(abi.encodePacked(uint64(2), c.proof.digests[0], folded));
        }
        c.root = _hash(abi.encodePacked(uint64(c.proof.leaves), folded));
    }

    /// @dev Encode the unsigned base-128 lengths and floors used by variable operations.
    function varint(uint256 value) internal pure returns (bytes memory encoded) {
        do {
            uint8 digit = uint8(value & 127);
            value >>= 7;
            encoded = abi.encodePacked(encoded, bytes1(value == 0 ? digit : digit | 128));
        } while (value != 0);
    }

    /// @dev Bootstrap commits authenticate absent metadata and a zero inactivity floor.
    function test_BootstrapCommit() public view {
        bytes memory fixedCommit = abi.encodePacked(hex"0000", bytes32(0), uint64(0));
        rejectMutations(smallCase(fixedCommit, false));
        rejectMutations(smallCase(hex"000000", false));
    }

    /// @dev Each of the nine fixed append padding bytes contributes to the commitment.
    function test_FixedAppendPadding() public view {
        bytes memory operation = abi.encodePacked(hex"01", bytes32(uint256(71)), bytes9(0));
        assertEq(operation.length, 42);
        KeylessCase memory c = smallCase(operation, true);
        rejectMutations(c);
        for (uint256 i = 33; i < operation.length; ++i) {
            operation[i] = 0x01;
            assertFalse(this.checked(c), "append padding is not bound");
            operation[i] = 0x00;
        }
    }

    /// @dev Payload boundaries cover positioned hash words and variable length-prefix transitions.
    function test_VariableBytePayloadBoundaries() public view {
        uint256[13] memory lengths = [uint256(0), 1, 22, 23, 24, 30, 31, 32, 33, 127, 128, 255, 256];
        for (uint256 i; i < lengths.length; ++i) {
            bytes memory payload = new bytes(lengths[i]);
            for (uint256 j; j < payload.length; ++j) {
                payload[j] = bytes1(uint8(j));
            }
            bytes memory value = abi.encodePacked(varint(payload.length), payload);
            for (uint256 kind; kind < 2; ++kind) {
                bytes memory operation =
                    kind == 0 ? abi.encodePacked(hex"01", value) : abi.encodePacked(hex"0001", value, hex"01");
                KeylessCase memory c = smallCase(operation, true);
                rejectMutations(c);
                for (uint256 j; j < varint(payload.length).length; ++j) {
                    uint256 prefix = kind + 1 + j;
                    operation[prefix] ^= 0x01;
                    assertFalse(this.checked(c), "variable length prefix is not bound");
                    operation[prefix] ^= 0x01;
                }
            }
        }
    }

    /// @dev Both metadata variants bind a nonzero floor in fixed and variable encodings.
    function test_NonzeroFloorCommit() public view {
        bytes32 metadata = bytes32(uint256(99));
        rejectMutations(smallCase(abi.encodePacked(hex"0000", bytes32(0), uint64(1)), true));
        rejectMutations(smallCase(abi.encodePacked(hex"0001", metadata, uint64(1)), true));
        rejectMutations(smallCase(hex"000001", true));
        rejectMutations(smallCase(hex"00010311223301", true));
    }

    /// @dev Inclusion authenticates opaque bytes without imposing an operation parser.
    function testFuzz_OpaqueOperation(bytes memory operation, bool second) public view {
        KeylessCase memory c = smallCase(operation, second);
        assertTrue(this.checked(c));
        c.operation = abi.encodePacked(operation, bytes1(0));
        assertFalse(this.checked(c), "operation length is not bound");
    }

    /// @dev Commitments, exact witness consumption, and all coordinates are authenticated.
    function rejectMutations(KeylessCase memory c) internal view {
        uint256 leaves = c.proof.leaves;
        assertTrue(this.checked(c));
        c.root ^= bytes32(uint256(1));
        assertFalse(this.checked(c), "wrong root accepted");
        c.root ^= bytes32(uint256(1));
        bytes memory operation = c.operation;
        c.operation = abi.encodePacked(operation, bytes1(0));
        assertFalse(this.checked(c), "wrong operation accepted");
        c.operation = operation;
        if (operation.length != 0) {
            bytes memory truncated = new bytes(operation.length - 1);
            for (uint256 i; i < truncated.length; ++i) {
                truncated[i] = operation[i];
            }
            c.operation = truncated;
            assertFalse(this.checked(c), "truncated operation accepted");
            c.operation = operation;
        }
        if (operation.length != 0) {
            operation[0] ^= 0x01;
            assertFalse(this.checked(c), "modified operation tag accepted");
            operation[0] ^= 0x01;
            operation[operation.length / 2] ^= 0x01;
            assertFalse(this.checked(c), "modified operation byte accepted");
            operation[operation.length / 2] ^= 0x01;
        }
        uint256 inactive = c.proof.inactivePeaks;
        c.proof.inactivePeaks = type(uint256).max;
        assertFalse(this.checked(c), "oversized inactive count accepted");
        c.proof.inactivePeaks = inactive;
        for (uint256 i; i < c.proof.digests.length; ++i) {
            c.proof.digests[i] ^= bytes32(uint256(1));
            assertFalse(this.checked(c), "wrong witness accepted");
            c.proof.digests[i] ^= bytes32(uint256(1));
        }
        bytes32[] memory original = c.proof.digests;
        for (uint256 mode; mode < 2; ++mode) {
            if (mode == 1 && original.length == 0) continue;
            c.proof.digests = new bytes32[](mode == 0 ? original.length + 1 : original.length - 1);
            for (uint256 i; i < original.length && i < c.proof.digests.length; ++i) {
                c.proof.digests[i] = original[i];
            }
            assertFalse(this.checked(c), "wrong witness count accepted");
        }
        c.proof.digests = original;
        uint256 location = c.proof.location;
        if (c.proof.leaves > 1) {
            c.proof.location = (location + 1) % c.proof.leaves;
            assertFalse(this.checked(c), "wrong location accepted");
            c.proof.location = location;
        }
        ++c.proof.leaves;
        assertFalse(this.checked(c), "wrong leaf count accepted");
        --c.proof.leaves;
        c.proof.location = c.proof.leaves;
        assertFalse(this.checked(c), "out of bounds location accepted");
        c.proof.location = type(uint256).max;
        assertFalse(this.checked(c), "oversized location accepted");
        c.proof.location = 0;
        c.proof.leaves = 0;
        assertFalse(this.checked(c), "empty tree accepted");
        c.proof.leaves = (uint256(1) << 62) + (_family() == LibMerkle.Family.MMB ? 31 : 1);
        assertFalse(this.checked(c), "unsupported leaf count accepted");
        c.proof.leaves = type(uint256).max;
        assertFalse(this.checked(c), "oversized leaf count accepted");
        c.proof.leaves = leaves;
        c.proof.location = location;
    }

    /// @dev The Rust oracle verifies each emitted proof with the production keyless operation type.
    function generate(
        uint256 leaves,
        uint256 location,
        uint256 floor,
        uint256 seed,
        Encoding encoding,
        KeylessOperation operation
    ) internal returns (KeylessCase memory c) {
        string[] memory args = new string[](encoding == Encoding.Variable ? 19 : 17);
        args[0] = string.concat(vm.projectRoot(), "/../target/release/commonware-sol-fuzz");
        args[1] = "qmdb";
        args[2] = "keyless";
        args[3] = "--leaves";
        args[4] = vm.toString(leaves);
        args[5] = "--location";
        args[6] = vm.toString(location);
        args[7] = "--seed";
        args[8] = vm.toString(seed);
        args[9] = "--inactivity-floor";
        args[10] = vm.toString(floor);
        args[11] = "--family";
        args[12] = _family() == LibMerkle.Family.MMB ? "mmb" : "mmr";
        args[13] = "--encoding";
        args[14] = encoding == Encoding.Variable ? "variable" : "fixed";
        args[15] = "--operation";
        args[16] = operation == KeylessOperation.Append
            ? "append"
            : operation == KeylessOperation.Commit ? "commit" : "commit-metadata";
        if (encoding == Encoding.Variable) {
            uint256[8] memory lengths = [uint256(0), 1, 31, 32, 33, 127, 128, 129];
            args[17] = "--value-length";
            args[18] = vm.toString(lengths[seed % lengths.length]);
        }
        (c.root, c.proof.leaves, c.proof.location, c.proof.inactivePeaks, c.proof.digests, c.operation) =
            abi.decode(_ffi(args), (bytes32, uint256, uint256, uint256, bytes32[], bytes));
        assertEq(c.proof.leaves, leaves);
        assertEq(c.proof.location, location);
    }

    /// @dev Production codecs and roots agree with independently encoded bootstrap commits.
    function test_DifferentialBootstrapCommit() public {
        for (uint256 encodingIndex; encodingIndex <= uint256(Encoding.Variable); ++encodingIndex) {
            Encoding encoding = Encoding(encodingIndex);
            KeylessCase memory c = generate(1, 0, 0, 71, encoding, KeylessOperation.Commit);
            bytes memory expected =
                encoding == Encoding.Fixed ? abi.encodePacked(hex"0000", bytes32(0), uint64(0)) : bytes(hex"000000");
            assertEq(c.operation, expected);
            assertEq(c.root, smallCase(expected, false).root);
            rejectMutations(c);
        }
    }

    /// @dev Rust proofs exercise both operation encodings at merge and peak boundaries.
    function test_DifferentialBoundaryTrees() public {
        uint256[10] memory sizes = [uint256(1), 2, 7, 8, 255, 256, 257, 383, 512, 1023];
        for (uint256 encodingIndex; encodingIndex <= uint256(Encoding.Variable); ++encodingIndex) {
            Encoding encoding = Encoding(encodingIndex);
            for (uint256 i; i < sizes.length; ++i) {
                assertTrue(this.checked(generate(sizes[i], 0, 0, 71, encoding, KeylessOperation.Commit)));
                if (sizes[i] > 1) {
                    assertTrue(this.checked(generate(sizes[i], sizes[i] - 1, 0, 71, encoding, KeylessOperation.Append)));
                }
            }
        }
    }

    /// @dev Rust byte-vector encodings cover length-prefix transitions for appends and commit metadata.
    function test_DifferentialVariablePayloadBoundaries() public {
        uint256[8] memory lengths = [uint256(0), 1, 31, 32, 33, 127, 128, 129];
        for (uint256 seed; seed < lengths.length; ++seed) {
            for (
                uint256 operationIndex;
                operationIndex <= uint256(KeylessOperation.CommitMetadata);
                operationIndex += 2
            ) {
                KeylessOperation operation = KeylessOperation(operationIndex);
                KeylessCase memory c = generate(2, 1, 0, seed, Encoding.Variable, operation);
                uint256 framing = operation == KeylessOperation.Append ? 1 : 3;
                assertEq(c.operation.length, framing + varint(lengths[seed]).length + lengths[seed]);
                rejectMutations(c);
            }
        }
    }

    /// @dev A distinct merge history must not authenticate under the other tree family.
    function rejectOtherFamily(KeylessCase calldata c) external view {
        bool valid = _family() == LibMerkle.Family.MMB
            ? LibQMDBKeylessMMR.verify(c.root, c.operation, c.proof, _hasher())
            : LibQMDBKeylessMMB.verify(c.root, c.operation, c.proof, _hasher());
        assertFalse(valid, "proof accepted by the other append family");
    }

    /// @dev Nonzero floors and optional commit metadata authenticate inactive peak boundaries.
    function test_DifferentialInactiveCommits() public {
        uint256[3] memory floors = [uint256(512), 768, 1280];
        for (uint256 encodingIndex; encodingIndex <= uint256(Encoding.Variable); ++encodingIndex) {
            Encoding encoding = Encoding(encodingIndex);
            for (
                uint256 operationIndex = uint256(KeylessOperation.Commit);
                operationIndex <= uint256(KeylessOperation.CommitMetadata);
                ++operationIndex
            ) {
                KeylessOperation operation = KeylessOperation(operationIndex);
                for (uint256 i; i < floors.length; ++i) {
                    uint256 n = i == 2 ? 1535 : 1023;
                    KeylessCase memory c = generate(n, n - 1, floors[i], 71, encoding, operation);
                    assertGt(c.proof.inactivePeaks, 0, "fixture has no inactive peaks");
                    rejectMutations(c);
                    uint256 inactive = c.proof.inactivePeaks;
                    c.proof.inactivePeaks = 0;
                    assertFalse(this.checked(c), "inactive boundary is not bound");
                    c.proof.inactivePeaks = inactive + 1;
                    assertFalse(this.checked(c), "wrong inactive count accepted");
                }
            }
        }
    }

    /// @dev Deep valid proofs bind their witnesses and tree family for append operations.
    function test_DifferentialProofMutations() public {
        for (uint256 encodingIndex; encodingIndex <= uint256(Encoding.Variable); ++encodingIndex) {
            Encoding encoding = Encoding(encodingIndex);
            KeylessCase memory c = generate(256, 255, 0, 71, encoding, KeylessOperation.Append);
            rejectMutations(c);
            this.rejectOtherFamily(c);
        }
    }

    /// @dev Random logs compare operation kinds, encodings, locations and inactivity floors with Rust.
    function testFuzz_DifferentialTrees(
        uint16 sizeSeed,
        uint16 locationSeed,
        uint16 floorSeed,
        uint64 seed,
        Encoding encoding,
        uint8 kindSeed
    ) public {
        uint256 n = uint256(sizeSeed) % 1536 + 1;
        uint256 floor = uint256(floorSeed) % n;
        uint256 location = floor + uint256(locationSeed) % (n - floor);
        KeylessOperation operation = location == 0 ? KeylessOperation.Commit : KeylessOperation(uint256(kindSeed) % 3);
        KeylessCase memory c = generate(n, location, floor, seed, encoding, operation);
        assertTrue(this.checked(c));
        c.operation = abi.encodePacked(c.operation, bytes1(0));
        assertFalse(this.checked(c), "modified oracle operation accepted");
    }
}

abstract contract LibQMDBKeylessMMBTest is LibQMDBKeylessTest {
    function _family() internal pure override returns (LibMerkle.Family) {
        return LibMerkle.Family.MMB;
    }
}

contract LibQMDBKeylessMMBKeccak256Test is LibQMDBKeylessMMBTest {
    function _hasher() internal pure override returns (address) {
        return address(0);
    }
}

contract LibQMDBKeylessMMBSha256Test is LibQMDBKeylessMMBTest {
    function _hasher() internal pure override returns (address) {
        return address(2);
    }
}

abstract contract LibQMDBKeylessMMRTest is LibQMDBKeylessTest {
    function _family() internal pure override returns (LibMerkle.Family) {
        return LibMerkle.Family.MMR;
    }
}

contract LibQMDBKeylessMMRKeccak256Test is LibQMDBKeylessMMRTest {
    function _hasher() internal pure override returns (address) {
        return address(0);
    }
}

contract LibQMDBKeylessMMRSha256Test is LibQMDBKeylessMMRTest {
    function _hasher() internal pure override returns (address) {
        return address(2);
    }
}
