// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.15;

import { Test } from "forge-std/Test.sol";
import { LibBLS12381 as BLS } from "../src/certificate/LibBLS12381.sol";
import { LibSimplex as Simplex } from "../src/simplex/LibSimplex.sol";

/// @dev External calls exercise the complete Simplex wrapper across the ABI boundary.
contract SimplexHarness {
    function verify(
        bool minSig,
        bytes calldata signature,
        bytes memory key,
        bytes memory namespace,
        Simplex.Subject memory subject
    ) external view returns (bool) {
        return minSig
            ? Simplex.verifyMinSig(signature, abi.decode(key, (BLS.G2Point)), namespace, subject)
            : Simplex.verifyMinPk(signature, abi.decode(key, (BLS.G1Point)), namespace, subject);
    }
}

contract LibSimplexTest is Test {
    struct Case {
        bytes signature;
        bytes key;
        bytes message;
        bytes point;
    }

    SimplexHarness internal harness;

    function setUp() public {
        harness = new SimplexHarness();
    }

    /// @dev Check the signed transcript against explicit domain, varint, and payload bytes.
    function test_EncodeMessage() public pure {
        bytes32 payload = bytes32(uint256(42));
        Simplex.Subject memory subject = Simplex.Subject({
            kind: Simplex.Kind.Finalization, epoch: 128, viewNumber: 300, parent: 127, payload: payload
        });
        assertEq(
            Simplex.encodeMessage(hex"0102", subject),
            bytes.concat(hex"0b0102", bytes("_FINALIZE"), hex"8001ac027f", payload)
        );

        subject = Simplex.Subject({
            kind: Simplex.Kind.Nullification, epoch: 0, viewNumber: type(uint64).max, parent: 123, payload: payload
        });
        assertEq(
            Simplex.encodeMessage("", subject), bytes.concat(hex"08", bytes("_NULLIFY"), hex"00ffffffffffffffffff01")
        );

        bytes memory namespace = new bytes(119);
        subject =
            Simplex.Subject({ kind: Simplex.Kind.Notarization, epoch: 0, viewNumber: 0, parent: 0, payload: payload });
        bytes memory message = Simplex.encodeMessage(namespace, subject);
        assertEq(message[0], bytes1(0x80));
        assertEq(message[1], bytes1(0x01));
    }

    /// @dev Nullification transcripts contain no proposal parent or payload.
    function test_NullificationIgnoresProposal() public pure {
        Simplex.Subject memory first = Simplex.Subject({
            kind: Simplex.Kind.Nullification, epoch: type(uint64).max, viewNumber: 128, parent: 0, payload: bytes32(0)
        });
        Simplex.Subject memory second = Simplex.Subject({
            kind: Simplex.Kind.Nullification,
            epoch: type(uint64).max,
            viewNumber: 128,
            parent: type(uint64).max,
            payload: bytes32(type(uint256).max)
        });
        assertEq(Simplex.encodeMessage(bytes("simplex"), first), Simplex.encodeMessage(bytes("simplex"), second));
    }

    /// @dev Verify generated certificates and reject every changed Simplex signing input.
    function testFuzz_DifferentialCertificate(
        bool minSig,
        uint8 kind,
        bytes memory namespace,
        uint64 epoch,
        uint64 viewNumber,
        uint64 parent,
        bytes32 payload,
        uint64 seed
    ) public {
        Simplex.Subject memory subject = Simplex.Subject({
            kind: Simplex.Kind(kind % 3), epoch: epoch, viewNumber: viewNumber, parent: parent, payload: payload
        });
        Case memory c = _generate(minSig, namespace, subject, seed);
        _assertCertificateInputs(minSig, c, namespace, subject);
    }

    /// @dev Exercise every vote domain and varint boundary for both signature variants.
    function test_DifferentialDomains() public {
        for (uint256 family = 0; family != 2; ++family) {
            for (uint256 kind = 0; kind != 3; ++kind) {
                bytes memory namespace = new bytes(119);
                Simplex.Subject memory subject = Simplex.Subject({
                    kind: Simplex.Kind(kind),
                    epoch: type(uint64).max,
                    viewNumber: 128,
                    parent: 127,
                    payload: bytes32(uint256(7))
                });
                Case memory c = _generate(family == 0, namespace, subject, 9);
                _assertCertificateInputs(family == 0, c, namespace, subject);
            }
        }
    }

    /// @dev Measure each complete wrapper with a finalization subject and trusted epoch key.
    function test_DifferentialGas() public {
        for (uint256 family = 0; family != 2; ++family) {
            bool minSig = family == 0;
            bytes memory namespace = bytes("simplex");
            Simplex.Subject memory subject = Simplex.Subject({
                kind: Simplex.Kind.Finalization, epoch: 1, viewNumber: 300, parent: 128, payload: bytes32(uint256(7))
            });
            Case memory c = _generate(minSig, namespace, subject, 9);
            assertTrue(harness.verify(minSig, c.signature, c.key, namespace, subject));
            vm.snapshotGasLastFrame("Simplex", minSig ? "minsig" : "minpk");
        }
    }

    /// @dev Check framing plus domain, subject, and namespace mutations.
    function _assertCertificateInputs(
        bool minSig,
        Case memory c,
        bytes memory namespace,
        Simplex.Subject memory subject
    ) internal view {
        assertEq(Simplex.encodeMessage(namespace, subject), c.message, "signing transcript mismatch");
        assertTrue(harness.verify(minSig, c.signature, c.key, namespace, subject));

        Simplex.Kind kind = subject.kind;
        subject.kind = Simplex.Kind((uint256(kind) + 1) % 3);
        assertFalse(harness.verify(minSig, c.signature, c.key, namespace, subject));
        subject.kind = kind;

        subject.epoch ^= 1;
        assertFalse(harness.verify(minSig, c.signature, c.key, namespace, subject));
        subject.epoch ^= 1;

        subject.viewNumber ^= 1;
        assertFalse(harness.verify(minSig, c.signature, c.key, namespace, subject));
        subject.viewNumber ^= 1;

        subject.parent ^= 1;
        assertEq(
            harness.verify(minSig, c.signature, c.key, namespace, subject), subject.kind == Simplex.Kind.Nullification
        );
        subject.parent ^= 1;

        subject.payload ^= bytes32(uint256(1));
        assertEq(
            harness.verify(minSig, c.signature, c.key, namespace, subject), subject.kind == Simplex.Kind.Nullification
        );
        subject.payload ^= bytes32(uint256(1));

        assertFalse(harness.verify(minSig, c.signature, c.key, bytes.concat(namespace, hex"00"), subject));
        assertTrue(harness.verify(minSig, c.signature, c.key, namespace, subject));
    }

    /// @dev Ask Commonware for a signed subject and its independently encoded transcript.
    function _generate(bool minSig, bytes memory namespace, Simplex.Subject memory subject, uint64 seed)
        internal
        returns (Case memory c)
    {
        string[] memory args = new string[](11);
        args[0] = _binary();
        args[1] = "simplex";
        args[2] = "generate";
        args[3] = minSig ? "minsig" : "minpk";
        args[4] = subject.kind == Simplex.Kind.Notarization
            ? "notarize"
            : subject.kind == Simplex.Kind.Nullification ? "nullify" : "finalize";
        args[5] = vm.toString(namespace);
        args[6] = vm.toString(uint256(subject.epoch));
        args[7] = vm.toString(uint256(subject.viewNumber));
        args[8] = vm.toString(uint256(subject.parent));
        args[9] = vm.toString(subject.payload);
        args[10] = vm.toString(uint256(seed));
        (c.signature, c.key, c.message, c.point) = abi.decode(vm.ffi(args), (bytes, bytes, bytes, bytes));
    }

    /// @dev Absolute FFI paths permit posix_spawn on macOS.
    function _binary() internal view returns (string memory) {
        return string.concat(vm.projectRoot(), "/../target/release/commonware-sol-fuzz");
    }
}
