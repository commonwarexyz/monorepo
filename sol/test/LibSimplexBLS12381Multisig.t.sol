// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.15;

import { Test } from "forge-std/Test.sol";
import { BLSVariant } from "./Common.t.sol";
import { LibBLS12381 as BLS } from "../src/certificate/LibBLS12381.sol";
import { LibSimplex as Simplex } from "../src/simplex/LibSimplex.sol";
import { LibSimplexBLS12381Multisig as Scheme } from "../src/simplex/LibSimplexBLS12381Multisig.sol";

/// @dev External calls exercise raw committee decoding and the complete Simplex wrapper.
contract SimplexBLS12381MultisigHarness {
    function verify(
        BLSVariant variant,
        bytes calldata signature,
        bytes calldata signers,
        bytes memory publicKeys,
        bytes memory namespace,
        Simplex.Subject memory subject
    ) external view returns (bool) {
        uint256 pointSize = variant == BLSVariant.MinSig ? 256 : 128;
        if (publicKeys.length % pointSize != 0) return false;
        if (variant == BLSVariant.MinSig) {
            BLS.G2Point[] memory g2 = abi.decode(
                bytes.concat(abi.encode(uint256(32), publicKeys.length / pointSize), publicKeys), (BLS.G2Point[])
            );
            return Scheme.verifyMinSig(signature, signers, g2, namespace, subject);
        }
        BLS.G1Point[] memory g1 = abi.decode(
            bytes.concat(abi.encode(uint256(32), publicKeys.length / pointSize), publicKeys), (BLS.G1Point[])
        );
        return Scheme.verifyMinPk(signature, signers, g1, namespace, subject);
    }
}

contract LibSimplexBLS12381MultisigTest is Test {
    struct Case {
        bytes signature;
        bytes publicKeys;
        bytes signers;
        bytes message;
    }

    SimplexBLS12381MultisigHarness internal harness;

    function setUp() public {
        harness = new SimplexBLS12381MultisigHarness();
    }

    /// @dev Empty and partial-point committees are rejected before quorum or ABI decoding.
    function test_InvalidCommitteeEncoding() public view {
        Simplex.Subject memory subject = _subject(Simplex.Kind.Finalization);
        assertFalse(harness.verify(BLSVariant.MinSig, new bytes(96), "", "", "simplex", subject));
        assertFalse(harness.verify(BLSVariant.MinPk, new bytes(192), "", "", "simplex", subject));
        assertFalse(harness.verify(BLSVariant.MinSig, new bytes(96), hex"01", hex"00", "simplex", subject));
        assertFalse(harness.verify(BLSVariant.MinPk, new bytes(192), hex"01", hex"00", "simplex", subject));
    }

    /// @dev Verify every vote domain and reject each field that belongs to its signed subject.
    function test_DifferentialDomainsAndSubjects() public {
        bytes memory namespace = new bytes(119);
        for (uint256 variantIndex; variantIndex <= uint256(BLSVariant.MinPk); ++variantIndex) {
            BLSVariant variant = BLSVariant(variantIndex);
            for (uint256 kind; kind != 3; ++kind) {
                Simplex.Subject memory subject = _subject(Simplex.Kind(kind));
                Case memory c = _generate(variant, namespace, subject, 9, 4, _signers(4, 3));
                _assertSubjectInputs(variant, c, namespace, subject);
            }
        }
    }

    /// @dev Signatures, signer selections, and ordered committee keys are authenticated together.
    function test_DifferentialCertificateMutations() public {
        bytes memory namespace = bytes("simplex");
        Simplex.Subject memory subject = _subject(Simplex.Kind.Notarization);
        for (uint256 variantIndex; variantIndex <= uint256(BLSVariant.MinPk); ++variantIndex) {
            BLSVariant variant = BLSVariant(variantIndex);
            Case memory c = _generate(variant, namespace, subject, 11, 4, _signers(4, 3));
            assertTrue(_verify(variant, c, namespace, subject));

            bytes memory signature = c.signature;
            c.signature = bytes.concat(signature);
            c.signature[0] ^= bytes1(uint8(1));
            assertFalse(_verify(variant, c, namespace, subject));
            c.signature = signature;

            bytes memory signers = c.signers;
            c.signers = bytes.concat(signers);
            c.signers[0] ^= bytes1(uint8(0x0c));
            assertFalse(_verify(variant, c, namespace, subject));
            c.signers = signers;

            bytes memory publicKeys = c.publicKeys;
            c.publicKeys = bytes.concat(publicKeys);
            c.publicKeys[0] ^= bytes1(uint8(1));
            assertFalse(_verify(variant, c, namespace, subject));
            c.publicKeys = _swap(publicKeys, variant == BLSVariant.MinSig ? 256 : 128, 0, 3);
            assertFalse(_verify(variant, c, namespace, subject));
        }
    }

    /// @dev Simplex quorums cover small and non-3f+1 committees and reject one fewer signer.
    function test_DifferentialQuorums() public {
        uint256[4] memory sizes = [uint256(1), 2, 3, 5];
        bytes memory namespace = bytes("simplex");
        Simplex.Subject memory subject = _subject(Simplex.Kind.Finalization);
        for (uint256 variantIndex; variantIndex <= uint256(BLSVariant.MinPk); ++variantIndex) {
            BLSVariant variant = BLSVariant(variantIndex);
            for (uint256 i; i != sizes.length; ++i) {
                uint256 participants = sizes[i];
                uint256 quorum = participants - (participants - 1) / 3;
                Case memory c = _generate(variant, namespace, subject, 13, participants, _signers(participants, quorum));
                assertTrue(_verify(variant, c, namespace, subject));
                if (quorum > 1) {
                    c = _generate(variant, namespace, subject, 13, participants, _signers(participants, quorum - 1));
                    assertFalse(_verify(variant, c, namespace, subject));
                }
            }
        }
    }

    /// @dev Measure quorum verification for the standard four-member configuration.
    function test_DifferentialGas() public {
        bytes memory namespace = bytes("simplex");
        Simplex.Subject memory subject = _subject(Simplex.Kind.Finalization);
        for (uint256 variantIndex; variantIndex <= uint256(BLSVariant.MinPk); ++variantIndex) {
            BLSVariant variant = BLSVariant(variantIndex);
            Case memory c = _generate(variant, namespace, subject, 9, 4, _signers(4, 3));
            assertTrue(_verify(variant, c, namespace, subject));
            vm.snapshotGasLastFrame(
                "SimplexBLS12381Multisig",
                variant == BLSVariant.MinSig ? "minsig_participants=4_signers=3" : "minpk_participants=4_signers=3"
            );
        }
    }

    function _assertSubjectInputs(
        BLSVariant variant,
        Case memory c,
        bytes memory namespace,
        Simplex.Subject memory subject
    ) internal view {
        assertEq(Simplex.encodeMessage(namespace, subject), c.message, "signing transcript mismatch");
        assertTrue(_verify(variant, c, namespace, subject));

        Simplex.Kind kind = subject.kind;
        subject.kind = Simplex.Kind((uint256(kind) + 1) % 3);
        assertFalse(_verify(variant, c, namespace, subject));
        subject.kind = kind;

        subject.epoch ^= 1;
        assertFalse(_verify(variant, c, namespace, subject));
        subject.epoch ^= 1;

        subject.viewNumber ^= 1;
        assertFalse(_verify(variant, c, namespace, subject));
        subject.viewNumber ^= 1;

        subject.parent ^= 1;
        assertEq(_verify(variant, c, namespace, subject), subject.kind == Simplex.Kind.Nullification);
        subject.parent ^= 1;

        subject.payload ^= bytes32(uint256(1));
        assertEq(_verify(variant, c, namespace, subject), subject.kind == Simplex.Kind.Nullification);
        subject.payload ^= bytes32(uint256(1));

        assertFalse(_verify(variant, c, bytes.concat(namespace, hex"00"), subject));
    }

    function _verify(BLSVariant variant, Case memory c, bytes memory namespace, Simplex.Subject memory subject)
        internal
        view
        returns (bool)
    {
        (bool ok, bytes memory result) = address(harness).staticcall{ gas: 2_000_000 }(
            abi.encodeCall(harness.verify, (variant, c.signature, c.signers, c.publicKeys, namespace, subject))
        );
        return ok && result.length == 32 && abi.decode(result, (bool));
    }

    /// @dev Ask Commonware for a multisignature and its independently encoded transcript.
    function _generate(
        BLSVariant variant,
        bytes memory namespace,
        Simplex.Subject memory subject,
        uint64 seed,
        uint256 participants,
        bytes memory signers
    ) internal returns (Case memory c) {
        string[] memory args = new string[](subject.kind == Simplex.Kind.Nullification ? 20 : 24);
        args[0] = _binary();
        args[1] = "simplex";
        args[2] = "generate";
        args[3] = "multisig";
        args[4] = "--variant";
        args[5] = variant == BLSVariant.MinSig ? "minsig" : "minpk";
        args[6] = "--kind";
        args[7] = subject.kind == Simplex.Kind.Notarization
            ? "notarize"
            : subject.kind == Simplex.Kind.Nullification ? "nullify" : "finalize";
        args[8] = "--namespace-hex";
        args[9] = vm.toString(namespace);
        args[10] = "--epoch";
        args[11] = vm.toString(uint256(subject.epoch));
        args[12] = "--view";
        args[13] = vm.toString(uint256(subject.viewNumber));
        uint256 offset = 14;
        if (subject.kind != Simplex.Kind.Nullification) {
            args[offset++] = "--parent";
            args[offset++] = vm.toString(uint256(subject.parent));
            args[offset++] = "--payload-hex";
            args[offset++] = vm.toString(subject.payload);
        }
        args[offset++] = "--participants";
        args[offset++] = vm.toString(participants);
        args[offset++] = "--signers";
        args[offset++] = vm.toString(signers);
        args[offset++] = "--seed";
        args[offset] = vm.toString(uint256(seed));
        (c.signature, c.publicKeys, c.signers, c.message) = abi.decode(vm.ffi(args), (bytes, bytes, bytes, bytes));
    }

    function _subject(Simplex.Kind kind) internal pure returns (Simplex.Subject memory) {
        return Simplex.Subject({
            kind: kind, epoch: type(uint64).max, viewNumber: 128, parent: 127, payload: bytes32(uint256(7))
        });
    }

    function _signers(uint256 participants, uint256 count) internal pure returns (bytes memory signers) {
        signers = new bytes((participants + 7) / 8);
        for (uint256 i; i != count; ++i) {
            signers[i / 8] |= bytes1(uint8(1 << (i % 8)));
        }
    }

    function _swap(bytes memory values, uint256 width, uint256 a, uint256 b)
        internal
        pure
        returns (bytes memory result)
    {
        result = bytes.concat(values);
        for (uint256 i; i != width; ++i) {
            (result[a * width + i], result[b * width + i]) = (result[b * width + i], result[a * width + i]);
        }
    }

    /// @dev Absolute FFI paths permit posix_spawn on macOS.
    function _binary() internal view returns (string memory) {
        return string.concat(vm.projectRoot(), "/../target/release/commonware-sol-fuzz");
    }
}
