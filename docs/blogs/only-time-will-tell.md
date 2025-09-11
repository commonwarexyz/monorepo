# Binding Timelock Encryption: Only Time Will Tell

As your parents insisted when you were growing up, good things come to those that wait. It turns out recent advances in cryptography have proven them right.

When competing head-to-head, publicly revealing your move to an opponent (before they've done the same) offers an obvious advantage. This applies the same to a game of rock-paper-scissors as it does an keyword auction on your search result. Applications running games or contests blind submissions until some time period has elapsed to ensure fairness.

Blockchains, unlike the centralized infrastructure that traditionally provides this blinding to participants, don't yet offer this same "temporal privacy". Transactions submitted to onchain auctions are public the moment they hit the mempool. To see the value of this information leakage, look no further than the meteoric rise of MEV bots that monitor mempools, frontrun trades, and sandwich transactions.

What if blockchains could run fair games and contests?

## The Missing Primitive: Binding Timelock Encryption (BTLE)

Enter [(Practical) Timelock Encryption (TLE)](https://eprint.iacr.org/2023/189). TLE enables anyone to encrypt some data to a specific time in the future, typically a known index when some VRF output is revealed. When published, any observer can use this VRF output to decrypt the ciphertext provided by the user.

Think rock-paper-scissors, again. Two players can encrypt their moves for the same point in the future. Prior to that point, neither player knows what the other player chose (so sharing their move at any time prior to decryption offers no advantage). Once that point is reached, both players can decrypt their moves simultaneously using the corresponding VRF output (no collaboration with the other required).

TLE, a standalone cryptographic primitive, lacks the ability to enforce commitments to encrypted data. Nothing prevents a user from sharing different encrypted data to different people or encrypting updated data if they change their mind. What we really need is "Binding Timelock Encryption" (BTLE).

Embedded into a blockchain, TLE commitments become binding (BTLE). Submit an encrypted ciphertext before the end of a contest, and you can't back out or change your mind. Anyone possessing the VRF output associated with the end of the contest can decrypt the ciphertext and reveal the commitments (no interaction required).

Unlike commit-reveal schemes, TLE removes the "free option" any participant has to hide their reveal (if, say, revealing a commitment isn't in their favor). Consider an auction with 3 people bidding. Player 1 commits to 10, Player 2 commits to 20, Player 3 commits to 30. Player 3 waits for Player 1 and Player 2 to reveal their bids, and then determines not to reveal because 30 overvalued the item.

With BTLE, blockchains can finally offer temporal privacy. Good things (or fair contests onchain), as your parents said, come to those that wait.

## BATTLEWARE: Proving BTLE is Practical

To demonstrate just how useful BTLE is, we built [BATTLEWARE](https://battleware.xyz). BATTLEWARE is an onchain game where players battle each other for bragging rights on a global leaderboard.

We wanted to make TLE tangible—something you could experience, not just read about in papers. So we built Battleware: a fighting game where temporal privacy isn't a feature, it's the foundation.

Think Street Fighter, but onchain. Two players face off in turn-based combat. Each round, both players select their moves—attack, defend, special ability—and encrypt them to the same future block. Neither knows what the other chose. When that block arrives, both moves decrypt simultaneously and resolve against each other. Punch beats grab. Grab beats block. Block beats punch.

The beauty is in the simplicity. Players just pick their move and submit. No waiting for opponents to reveal. No games abandoned because someone rage quit. No advantage for moving last. The blockchain becomes a perfect referee—impartial, unstoppable, and always on time.

But Battleware goes further. Each move's effectiveness gets scaled by the VRF output from the revealing block, adding controlled randomness to combat. Your character itself—appearance, stats, abilities—is generated from the VRF of your first transaction's block. Even matchmaking uses VRF to prevent players from manipulating who they face. Every element that needs fairness gets it through cryptography, not trust.

This isn't a tech demo pretending to be a game. It's a real game that happens to demonstrate what becomes possible when you build temporal privacy directly into consensus. No coordinator server. No session management. No player availability requirements. Just pure competitive gameplay where only time will tell who wins.

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

TODO: this isn't really about the topic of this article anymore?

A few years ago, Moxie Marlinspike wrote about his first impressions of web3. He observed that users won't run their own servers, so we need to "design systems that can distribute trust without having to distribute infrastructure." With Battleware, we're getting close. Users interact with a fully decentralized application through their browser, trusting only the validators, with no need to run any infrastructure themselves.

More importantly, Battleware demonstrates what becomes possible when you treat blockchain primitives as components to be assembled, not layers to be stacked. When you can embed a VRF directly into consensus, timelock encryption becomes practical. When you can customize execution, you can decrypt in parallel. When you control the networking layer, you can implement rate limiting instead of fees.

This is the promise of specialization. Not another general-purpose chain trying to be everything to everyone, but focused applications that do exactly what they need to do, exceptionally well.

## What's Next

Battleware is just the beginning. It showcases binding timelock encryption and embedded randomness, but there's so much more to explore. State sync. Reconfiguration. New cryptographic schemes. Different consensus mechanisms.

At Commonware, we believe the best onchain experiences will emerge from developers who refuse to accept the limitations of today's frameworks. Who see blockchain components not as fixed infrastructure but as malleable primitives. Who understand that in distributed systems, as in life, timing is everything.

Want to try it yourself? Head to [battleware.xyz](https://battleware.xyz) and generate your fighter. No wallet needed. No fees required. Just pure onchain combat where only time will tell who wins.

*The code is at [github.com/commonwarexyz/battleware](https://github.com/commonwarexyz/battleware). PRs welcome—let's build the future of specialized blockchains together.*
