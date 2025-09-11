# Only Time Will Tell

As your parents noted when you were growing up, good things come to those that wait. It turns out that recent advances in cryptography, however, have proven them right.

When competing head-to-head, publicly revealing your play to an opponent (before they've gone) offers an obvious advantage. This applies the same to a battle of rock-paper-scissors as it does an auction for ads. Consequently, applications involving some sort of contest often operate as a trusted facilitator. Google runs the ad auction so Amazon doesn't learn what Walmart is bidding.

Blockchains don't yet offer this same "temporal privacy" (the ability to hide information until a specific moment when all participants' actions are revealed simultaneously). Every transaction is public the moment it hits the mempool. The meteoric rise of MEV bots that monitor mempools, frontrun trades, and sandwich transactions conveys everything you need to know about the value of this information leakage.

## The Missing Primitive: Timelock Encryption

What if a user could produce a binding commitment to a specific moment in the future? Reveled at a given time, whether they are ready or not? Meet [Timelock Encryption (TLE)](https://eprint.iacr.org/2023/189).

TLE lets you encrypt data to a future moment in time. The ciphertext can only be decrypted when that moment arrives—not before, not by choice, but automatically when the target time is reached.

Here's how it works: You encrypt your data to a specific block height using the expected properties of that future block. When the network finalizes that block, its unique properties (like a VRF output) become the decryption key. Anyone can take your ciphertext and the block's public output to recover the plaintext. The decryption isn't optional—once the block exists, the data is decryptable.

The cryptographic construction ensures two critical properties. First, no one can decrypt before the target block is finalized, not even the encryptor. Second, everyone can decrypt after the target block is finalized, using only public information from the chain. The network's progression through time becomes the decryption mechanism itself.

In practice, this means you submit an encrypted move targeting block 1000. When block 1000 is finalized with its VRF output, that output directly enables decryption. No interaction required. No secrets to store. No ability to withhold revelation. Time passes, the block arrives, and your move is revealed.

_Difference from commit-reveal? The commiter isn't tasked with revealing._

## Enter Battleware

Over the last few months, we've made substantial progress building out the Commonware Library. We wanted to build something that showcased capability rather than capacity. Something that demonstrated what becomes possible when you can mold the stack to your application, not the other way around.

Battleware is that demonstration: a fully onchain fighting game where time itself decrypts your moves.

When you play Battleware, you encrypt your moves to a future block height. Not to a secret. Not to a committee. To a moment in time that hasn't happened yet. When that block arrives, the network's embedded VRF generates the decryption key. Your move is revealed, scaled by randomness, and executed—all without you having to come back online.

This changes everything. Timelock encryption provides forced revelation—once encrypted to a future time, the data will be revealed when that time arrives, no matter what. Anyone can trigger the decryption using the VRF output from the target block. The player who submitted it can't prevent it. They can't selectively withhold it. They can't even be offline to stop it.

No trusted coordinator. No remembering secrets. No stalled games from players who disappear. Just submit your move and let time handle the rest.

## How It Works

Everything starts when you submit your first transaction: `Instruction::Generate()`. The block that includes your transaction uses its VRF output to randomly generate your character—appearance, name, powers, everything. Not predetermined. Not manipulable. Born from the entropy of consensus itself.

After matchmaking pairs you with an opponent (again using the VRF to prevent gaming the system), you enter battle. Fifteen rounds of combat, unless someone gets KO'd first. Each round, you encrypt your move to expire at a specific view in the future. When that view passes, anyone can submit a settle transaction that decrypts both players' moves and resolves the round.

Miss your window? The game defaults you to no action and continues. Your opponent can't stall you out. The battle always progresses.

The real magic happens in the block finalization. Unlike traditional commit-reveal schemes where users must return to reveal their secrets, Battleware's timelock encryption means the network itself becomes the revealer. The VRF output from finalizing each block serves as the decryption key for any moves targeted at that height.

## Under the Hood

Battleware combines nearly every primitive in the Commonware Library—plus a few new ones we built along the way. Running across 50 validators distributed in 10 regions globally, it delivers the responsiveness you'd expect from a game, not a blockchain.

The architecture breaks from traditional blockchain patterns in several key ways:

**No gas fees or faucets.** Network entrypoints rate-limit inclusion instead of charging fees. Just start playing—no token balance required. In the future, imagine monthly subscriptions that give you a certain amount of daily throughput. In an era of blockchain abundance, many applications don't need users fighting over block space.

**Trust-minimized frontend.** When you interact with Battleware, you only trust the validators. Every piece of state served to your browser comes authenticated with storage proofs and wrapped in threshold signatures. The backend can't lie to you about the game state even if it wanted to.

**Integrated indexing.** No more spinning up separate infrastructure to watch the chain. Validators push authenticated data directly to the backend, which processes anything with a valid threshold signature. This is trickier than it sounds—we can't generate signatures over roots until after execution completes because we need the VRF output from that block.

**Concurrent decryption.** To keep the game responsive, we decrypt moves in parallel during execution. When serving state, we generate multi-proofs on the fly—think of them as concatenated single proofs that efficiently represent collections of items across sparse ranges. Switch views and the stream dynamically adjusts from filtered to firehose mode.

To ensure there are always opponents available, we run bots that move randomly. Consider them tutorial mode for learning the game.

The entire implementation—all 11.2k lines of it—is [open source](https://github.com/commonwarexyz/battleware). The code is still rough around the edges, but we've got 77% test coverage and consider it an excellent opportunity to become a Commonware contributor.

## Beyond the Game

Battleware isn't really about the game. It's about what the game represents.

A few years ago, Moxie Marlinspike wrote about his first impressions of web3. He observed that users won't run their own servers, so we need to "design systems that can distribute trust without having to distribute infrastructure." With Battleware, we're getting close. Users interact with a fully decentralized application through their browser, trusting only the validators, with no need to run any infrastructure themselves.

More importantly, Battleware demonstrates what becomes possible when you treat blockchain primitives as components to be assembled, not layers to be stacked. When you can embed a VRF directly into consensus, timelock encryption becomes practical. When you can customize execution, you can decrypt in parallel. When you control the networking layer, you can implement rate limiting instead of fees.

This is the promise of specialization. Not another general-purpose chain trying to be everything to everyone, but focused applications that do exactly what they need to do, exceptionally well.

## What's Next

Battleware is just the beginning. It showcases binding timelock encryption and embedded randomness, but there's so much more to explore. State sync. Reconfiguration. New cryptographic schemes. Different consensus mechanisms.

At Commonware, we believe the best onchain experiences will emerge from developers who refuse to accept the limitations of today's frameworks. Who see blockchain components not as fixed infrastructure but as malleable primitives. Who understand that in distributed systems, as in life, timing is everything.

Want to try it yourself? Head to [battleware.xyz](https://battleware.xyz) and generate your fighter. No wallet needed. No fees required. Just pure onchain combat where only time will tell who wins.

*The code is at [github.com/commonwarexyz/battleware](https://github.com/commonwarexyz/battleware). PRs welcome—let's build the future of specialized blockchains together.*
