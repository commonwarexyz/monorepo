// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.15;

import { LibBLS12381 as BLS } from "../certificate/LibBLS12381.sol";
import { LibCodec } from "../codec/LibCodec.sol";

/// @notice Encode Commonware Simplex votes and calculate committee quorums.
/// @dev Payload digests are 32 bytes.
library LibSimplex {
    /// @dev The vote signing domain.
    enum Kind {
        Notarization,
        Nullification,
        Finalization
    }

    /// @notice The Simplex vote authenticated by a certificate.
    struct Subject {
        /// The vote domain required by the calling protocol.
        Kind kind;
        /// The epoch of the vote.
        uint64 epoch;
        /// The view of the vote.
        uint64 viewNumber;
        /// The proposal's parent view, ignored for nullifications.
        uint64 parent;
        /// The proposal's payload digest, ignored for nullifications.
        bytes32 payload;
    }

    /// @notice Minimum number of signers required by Simplex.
    /// @param count The nonzero committee size.
    function quorum(uint256 count) internal pure returns (uint256) {
        return count - (count - 1) / 3;
    }

    /// @notice Construct the exact signed bytes for a Simplex certificate.
    /// @dev Nullifications commit only to the epoch and view. Other votes also commit to the
    /// parent view and payload. The namespace length and integer fields use unsigned varints.
    function encodeMessage(bytes memory baseNamespace, Subject memory subject) internal pure returns (bytes memory) {
        return BLS.encodeMessage(namespace(baseNamespace, subject.kind), message(subject));
    }

    /// @notice Derive the vote signing namespace from the application namespace.
    function namespace(bytes memory baseNamespace, Kind kind) internal pure returns (bytes memory) {
        bytes memory suffix = kind == Kind.Notarization
            ? bytes("_NOTARIZE")
            : kind == Kind.Nullification ? bytes("_NULLIFY") : bytes("_FINALIZE");
        return bytes.concat(baseNamespace, suffix);
    }

    /// @notice Encode the round and, for notarizations and finalizations, the proposal.
    function message(Subject memory subject) internal pure returns (bytes memory) {
        bytes memory round =
            bytes.concat(LibCodec.encodeVarint(subject.epoch), LibCodec.encodeVarint(subject.viewNumber));
        if (subject.kind == Kind.Nullification) return round;
        return bytes.concat(round, LibCodec.encodeVarint(subject.parent), subject.payload);
    }
}
