// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.15;

import { Test } from "forge-std/Test.sol";
import { BLSVariant } from "./Common.t.sol";
import { LibBLS12381 as BLS } from "../src/certificate/LibBLS12381.sol";
import { LibSimplex as Simplex } from "../src/simplex/LibSimplex.sol";
import { LibSimplexBLS12381Threshold as Scheme } from "../src/simplex/LibSimplexBLS12381Threshold.sol";

/// @dev External calls exercise the complete Simplex wrapper across the ABI boundary.
contract SimplexBLS12381ThresholdHarness {
    function verify(
        BLSVariant variant,
        bytes calldata signature,
        bytes memory key,
        bytes memory namespace,
        Simplex.Subject memory subject
    ) external view returns (bool) {
        return variant == BLSVariant.MinSig
            ? Scheme.verifyMinSig(signature, abi.decode(key, (BLS.G2Point)), namespace, subject)
            : Scheme.verifyMinPk(signature, abi.decode(key, (BLS.G1Point)), namespace, subject);
    }
}

contract LibSimplexBLS12381ThresholdTest is Test {
    struct Case {
        bytes signature;
        bytes key;
        bytes message;
        bytes point;
    }

    SimplexBLS12381ThresholdHarness internal harness;

    function setUp() public {
        harness = new SimplexBLS12381ThresholdHarness();
    }

    /// @dev Verify generated certificates and reject every changed Simplex signing input.
    function testFuzz_DifferentialCertificate(
        BLSVariant variant,
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
        Case memory c = _generate(variant, namespace, subject, seed);
        _assertCertificateInputs(variant, c, namespace, subject);
    }

    /// @dev Exercise every vote domain and varint boundary for both signature variants.
    function test_DifferentialDomains() public {
        for (uint256 variantIndex; variantIndex <= uint256(BLSVariant.MinPk); ++variantIndex) {
            BLSVariant variant = BLSVariant(variantIndex);
            for (uint256 kind = 0; kind != 3; ++kind) {
                bytes memory namespace = new bytes(119);
                Simplex.Subject memory subject = Simplex.Subject({
                    kind: Simplex.Kind(kind),
                    epoch: type(uint64).max,
                    viewNumber: 128,
                    parent: 127,
                    payload: bytes32(uint256(7))
                });
                Case memory c = _generate(variant, namespace, subject, 9);
                _assertCertificateInputs(variant, c, namespace, subject);
            }
        }
    }

    /// @dev Measure each complete wrapper with a finalization subject and trusted epoch key.
    function test_DifferentialGas() public {
        for (uint256 variantIndex; variantIndex <= uint256(BLSVariant.MinPk); ++variantIndex) {
            BLSVariant variant = BLSVariant(variantIndex);
            bytes memory namespace = bytes("simplex");
            Simplex.Subject memory subject = Simplex.Subject({
                kind: Simplex.Kind.Finalization, epoch: 1, viewNumber: 300, parent: 128, payload: bytes32(uint256(7))
            });
            Case memory c = _generate(variant, namespace, subject, 9);
            assertTrue(harness.verify(variant, c.signature, c.key, namespace, subject));
            vm.snapshotGasLastFrame("SimplexBLS12381Threshold", variant == BLSVariant.MinSig ? "minsig" : "minpk");
        }
    }

    /// @dev Check framing plus domain, subject, and namespace mutations.
    function _assertCertificateInputs(
        BLSVariant variant,
        Case memory c,
        bytes memory namespace,
        Simplex.Subject memory subject
    ) internal view {
        assertEq(Simplex.encodeMessage(namespace, subject), c.message, "signing transcript mismatch");
        assertTrue(harness.verify(variant, c.signature, c.key, namespace, subject));

        Simplex.Kind kind = subject.kind;
        subject.kind = Simplex.Kind((uint256(kind) + 1) % 3);
        assertFalse(harness.verify(variant, c.signature, c.key, namespace, subject));
        subject.kind = kind;

        subject.epoch ^= 1;
        assertFalse(harness.verify(variant, c.signature, c.key, namespace, subject));
        subject.epoch ^= 1;

        subject.viewNumber ^= 1;
        assertFalse(harness.verify(variant, c.signature, c.key, namespace, subject));
        subject.viewNumber ^= 1;

        subject.parent ^= 1;
        assertEq(
            harness.verify(variant, c.signature, c.key, namespace, subject), subject.kind == Simplex.Kind.Nullification
        );
        subject.parent ^= 1;

        subject.payload ^= bytes32(uint256(1));
        assertEq(
            harness.verify(variant, c.signature, c.key, namespace, subject), subject.kind == Simplex.Kind.Nullification
        );
        subject.payload ^= bytes32(uint256(1));

        assertFalse(harness.verify(variant, c.signature, c.key, bytes.concat(namespace, hex"00"), subject));
        assertTrue(harness.verify(variant, c.signature, c.key, namespace, subject));
    }

    /// @dev Ask Commonware for a signed subject and its independently encoded transcript.
    function _generate(BLSVariant variant, bytes memory namespace, Simplex.Subject memory subject, uint64 seed)
        internal
        returns (Case memory c)
    {
        string[] memory args = new string[](subject.kind == Simplex.Kind.Nullification ? 16 : 20);
        args[0] = _binary();
        args[1] = "simplex";
        args[2] = "generate";
        args[3] = "threshold";
        args[4] = "--variant";
        args[5] = variant == BLSVariant.MinSig ? "minsig" : "minpk";
        args[6] = "--kind";
        args[7] = subject.kind == Simplex.Kind.Notarization
            ? "notarize"
            : subject.kind == Simplex.Kind.Nullification ? "nullify" : "finalize";
        args[8] = "--namespace";
        args[9] = vm.toString(namespace);
        args[10] = "--epoch";
        args[11] = vm.toString(uint256(subject.epoch));
        args[12] = "--view";
        args[13] = vm.toString(uint256(subject.viewNumber));
        uint256 offset = 14;
        if (subject.kind != Simplex.Kind.Nullification) {
            args[offset++] = "--parent";
            args[offset++] = vm.toString(uint256(subject.parent));
            args[offset++] = "--payload";
            args[offset++] = vm.toString(subject.payload);
        }
        args[offset++] = "--seed";
        args[offset++] = vm.toString(uint256(seed));
        (c.signature, c.key, c.message, c.point) = abi.decode(vm.ffi(args), (bytes, bytes, bytes, bytes));
    }

    /// @dev Absolute FFI paths permit posix_spawn on macOS.
    function _binary() internal view returns (string memory) {
        return string.concat(vm.projectRoot(), "/../target/release/commonware-sol-fuzz");
    }
}
