// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.15;

import { Test } from "forge-std/Test.sol";
import { LibSimplex as Simplex } from "../src/simplex/LibSimplex.sol";

contract LibSimplexTest is Test {
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
}
