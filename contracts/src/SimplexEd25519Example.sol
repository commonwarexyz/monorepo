// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {SimplexVerifierAttributable} from "./simplex_verifiers/SimplexVerifierAttributable.sol";
import {DigestLengths} from "./simplex_verifiers/SimplexVerifierBase.sol";
import {Ed25519Scheme} from "./signing_schemes/Ed25519Scheme.sol";
import {SimpleKeyStore} from "./keystore/SimpleKeyStore.sol";


contract SimplexEd25519Example is SimplexVerifierAttributable {
    constructor()
        SimplexVerifierAttributable(
            new SimpleKeyStore(new Ed25519Scheme()),
            DigestLengths.SHA256
        )
    {}
}
