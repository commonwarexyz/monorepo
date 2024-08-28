# commonware 

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE-MIT)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE-APACHE)
[![Rust](https://github.com/commonwarexyz/monorepo/actions/workflows/rust.yml/badge.svg)](https://github.com/commonwarexyz/monorepo/actions/workflows/rust.yml)
[![Discord Shield](https://discordapp.com/api/guilds/1274058657528680640/widget.png?style=shield)](https://discord.gg/wt5VtKXv5c)

## Primitives 

_Crates in this repository are designed for deployment in adversarial environments. If you find an exploit, please refer to our [security policy](./SECURITY.md) before disclosing it publicly (an exploit may equip a malicious party to attack users of a primitive)._

* [cryptography](./cryptography/README.md): Generate keys, sign arbitrary messages, and deterministically verify untrusted signatures.
* [p2p](./p2p/README.md): Communicate with authenticated peers over encrypted connections. 

## Examples

_Examples may include insecure code (i.e. deriving keypairs from an integer arguements) to make them easier to run. Examples are not intended to be used directly in production._

* [chat](./examples/chat/README.md): Send encrypted messages to a group of friends. 
* [vrf](./examples/vrf/README.md): Generate bias-resistant randomness with untrusted contributors.

## Licensing

This repository is dual-licensed under both the [Apache 2.0](./LICENSE-APACHE) and [MIT](./LICENSE-MIT) licenses. You may choose either license when using this code.