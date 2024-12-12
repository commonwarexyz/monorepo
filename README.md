# commonware

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE-MIT)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE-APACHE)
[![Coverage](https://codecov.io/gh/commonwarexyz/monorepo/graph/badge.svg?token=847TBNH49H)](https://codecov.io/gh/commonwarexyz/monorepo)
[![Discussions](https://img.shields.io/github/discussions/commonwarexyz/monorepo)](https://github.com/commonwarexyz/monorepo/discussions)

## Primitives

_Primitives are designed for deployment in adversarial environments. If you find an exploit, please refer to our [security policy](./SECURITY.md) before disclosing it publicly (an exploit may equip a malicious party to attack users of a primitive)._

* [consensus](./consensus/README.md): Order opaque messages in a Byzantine environment.
* [cryptography](./cryptography/README.md): Generate keys, sign arbitrary messages, and deterministically verify signatures.
* [p2p](./p2p/README.md): Communicate with authenticated peers over encrypted connections.
* [runtime](./runtime/README.md): Execute asynchronous tasks with a configurable scheduler.
* [storage](./storage/README.md): Persist and retrieve data from an abstract store.
* [stream](./stream/README.md): Exchange messages over arbitrary transport.

## Examples

_Examples may include insecure code (i.e. deriving keypairs from an integer arguments) to make them easier to run. Examples are not intended to be used directly in production._

* [chat](./examples/chat/README.md): Send encrypted messages to a group of friends.
* [log](./examples/log/README.md):  Commit to a secret log and agree to its hash.
* [vrf](./examples/vrf/README.md): Generate bias-resistant randomness with untrusted contributors.

## Miscellaneous

_Sometimes, we opt to maintain software that is neither a primitive nor an example to make it easier to interact with the Commonware Library. Unless otherwise indicated, code in this section is intended to be used in production. Please refer to our [security policy](./SECURITY.md) before disclosing an exploit publicly._

* [docs](./docs): Access information about Commonware at https://commonware.xyz.
* [macros](./macros/README.md): Augment the development of primitives with procedural macros.
* [utils](./utils/README.md): Leverage common functionality across multiple primitives.

## Licensing

This repository is dual-licensed under both the [Apache 2.0](./LICENSE-APACHE) and [MIT](./LICENSE-MIT) licenses. You may choose either license when employing this code.

## Contributing

We encourage external contributors to submit issues and pull requests to the Commonware Library. To learn more, please refer to our [contributing guidelines](./CONTRIBUTING.md).

All work is coordinated via the [tracker](https://github.com/orgs/commonwarexyz/projects/2). If something in [the backlog](https://github.com/orgs/commonwarexyz/projects/2/views/3) looks particularly useful, leave a comment so we can prioritize it!

## Support

If you have any questions about using the Commonware Library, we encourage you to post in [GitHub Discussions](https://github.com/commonwarexyz/monorepo/discussions). We're happy to help!