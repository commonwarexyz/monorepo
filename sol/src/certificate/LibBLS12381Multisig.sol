// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.15;

import { LibBLS12381 as BLS } from "./LibBLS12381.sol";

/// @notice Verify Commonware BLS12-381 multisignature certificates with EIP-2537.
/// @dev The caller must supply an ordered authenticated participant set with distinct BLS public
/// keys and authenticated identity-to-key bindings. Every key must be nonzero, in the correct
/// subgroup, and have a verified proof of possession. EIP-2537 addition does not check subgroups,
/// so verification relies on registration for key validation and proofs of possession.
/// Signer bitmaps contain exactly `ceil(publicKeys.length / 8)` bytes with unused high bits zero,
/// without Rust's encoded bitmap length prefix.
library LibBLS12381Multisig {
    /// @notice Verify a MinSig multisignature over a namespaced message.
    /// @param signature Uncompressed G1 coordinates `x || y`, each 48 bytes without padding.
    /// @param signers Raw bitmap indexed by `publicKeys`, least-significant bit first in each byte.
    /// @param publicKeys Ordered registered G2 public keys.
    /// @param quorum Minimum number of selected participants, chosen from trusted protocol context.
    /// @param namespace The signing namespace, without a length prefix.
    /// @param message The encoded subject, without namespace framing.
    /// @return valid Whether the bitmap is canonical, quorum is met, and the signature is valid.
    function verifyMinSig(
        bytes calldata signature,
        bytes calldata signers,
        BLS.G2Point[] memory publicKeys,
        uint256 quorum,
        bytes memory namespace,
        bytes memory message
    ) internal view returns (bool valid) {
        if (signature.length != 96) return false;
        uint256 n = publicKeys.length;
        if (!_validBitmap(signers, n, quorum)) return false;

        BLS.G2Point memory aggregate;
        for (uint256 i; i < n; ++i) {
            if (!_selected(signers, i)) continue;
            bool ok;
            (ok, aggregate) = BLS.addG2(aggregate, publicKeys[i]);
            if (!ok) return false;
        }
        return BLS.verifyMinSig(signature, aggregate, namespace, message);
    }

    /// @notice Verify a MinPk multisignature over a namespaced message.
    /// @param signature Uncompressed G2 coordinates `x.c0 || x.c1 || y.c0 || y.c1`, each 48 bytes.
    /// @param signers Raw bitmap indexed by `publicKeys`, least-significant bit first in each byte.
    /// @param publicKeys Ordered registered G1 public keys.
    /// @param quorum Minimum number of selected participants, chosen from trusted protocol context.
    /// @param namespace The signing namespace, without a length prefix.
    /// @param message The encoded subject, without namespace framing.
    /// @return valid Whether the bitmap is canonical, quorum is met, and the signature is valid.
    function verifyMinPk(
        bytes calldata signature,
        bytes calldata signers,
        BLS.G1Point[] memory publicKeys,
        uint256 quorum,
        bytes memory namespace,
        bytes memory message
    ) internal view returns (bool valid) {
        if (signature.length != 192) return false;
        uint256 n = publicKeys.length;
        if (!_validBitmap(signers, n, quorum)) return false;

        BLS.G1Point memory aggregate;
        for (uint256 i; i < n; ++i) {
            if (!_selected(signers, i)) continue;
            bool ok;
            (ok, aggregate) = BLS.addG1(aggregate, publicKeys[i]);
            if (!ok) return false;
        }
        return BLS.verifyMinPk(signature, aggregate, namespace, message);
    }

    /// @dev Validate participant bounds, bitmap framing, unused bits, and signer count.
    function _validBitmap(bytes calldata signers, uint256 n, uint256 quorum) private pure returns (bool) {
        if (n == 0 || n > type(uint32).max || quorum == 0 || quorum > n) return false;
        if (signers.length != (n + 7) >> 3) return false;

        uint256 usedBits = n & 7;
        if (usedBits != 0 && uint8(signers[signers.length - 1]) >> usedBits != 0) return false;

        uint256 count = 0;
        for (uint256 i; i < signers.length; ++i) {
            uint8 bits = uint8(signers[i]);
            while (bits != 0) {
                bits &= bits - 1;
                ++count;
            }
        }
        return count >= quorum;
    }

    /// @dev Return whether the participant at `index` is selected by the LSB-first bitmap.
    function _selected(bytes calldata signers, uint256 index) private pure returns (bool) {
        return uint256(uint8(signers[index >> 3])) & (uint256(1) << (index & 7)) != 0;
    }
}
