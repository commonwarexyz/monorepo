# Only Time Will Tell
As your parents noted when you were growing up, good things come to those that wait. It turns out that recent advances in cryptography, however, have proven your parents right.

When competing head-to-head, publicly revealing your play to an opponent (before they’ve gone) offers them an advantage. This applies the same to a battle of rock-paper-scissors as it does an auction for ads. Left with few (if any) alternatives, applications reliant on some sort of contest often operate as a trusted facilitator. Google doesn’t tell Amazon what Walmart is bidding to appear first in the search results for golf balls.

Blockchains

## Free Write


As your parents noted when you were growing up, many things can only be known after waiting (patiently) for time to pass.

Consider a round of rock-paper-scissors where players commit to moves in some order  the opponent can trivially select a move that wins.

Most applications that offer a sort of pvp dynamic serve as a blinder that ensures no participant has an advantage (and all players trust the application to be honest). Think bidding for ads on Google.


It turns out blockchains can now offer the same wisdom


It turns out they may have been on to something.



In the 90s, it turns out folks wanted to offer the same wisdom: https://cypherpunks.venona.com/date/1993/02/msg00129.html


Blockchains, until the release of


As your parents told you when you grew up,



You need temporal privacy. You just don’t know it yet.



Blockchains enforce binding commitments.

At Commonware, we believe that the best onchain experiences will develop a sustained edge through specialization. Why forego the flexibility of general-purpose execution?

When committing to private data, folks commonly use a commit-reveal scheme. At some elapsed time, participants reveal their commitment (or choose not to). What if instead you could have time be the revealer?


The key to any good joke is timing. Turns out the same can be said about blockchains.

Collaborating with others in a distributed system often requires committing to some value in secret and revealing your knowledge.

I like to play video games.

Goal: stateful example showcasing how to use commonware (no choice to not decrypt)
A Blockchain That Doesn’t Feel Like One (UNLIMITED ERA?)
Don’t recap, talk about now

Over the last few months, we’ve made substantial progress on building out the Commonware Library and recently hit the milestone of having enough to actually create an interactive chain.

We were blown away by the reaction to alto, our consensus benchmarking harness with wicked fast blocktimes.

Preparing for the unlimited era of crypto (tx fees enforced by network entrypoints that have a prepurchased capacity). I love micropayments but users want an unlimited option (and rate limited).

What to make? Instead of another TPS edification, we decided to do something to show capability rather than capacity (which at this point should more or less be table stakes for any new application).

This all started with some way to make Timelock Encryption into a useful demo (something I’ve felt for a few years is an exceptionally underutilized primitive, largely because it works best with an embedded VRF). Turns out we have one!

Next, the consideration was what to do with it? We had ideas that worked with value at stake (second price auctions) or required long time horizons (time capsule reveal) but none seemed like the right fit for a demo. I wanted something fast and fun and a contest. Enter Battleware.



Battleware required the combination of the vast majority of our primitives (and even some new ones). It took a little over a month and is all open-sourced here. The code is still rough around the edges (~11.2k LOC) but consider it an opportunity to become a commonware contributor! Still 77% test coverage.

https://github.com/commonwarexyz/battleware
https://deepwiki.com/commonwarexyz/battleware

Like alto, 50 validators globally distributed. 10 regions (us-west-1, us-east-1, eu-west-1, ap-northeast-1, eu-north-1, ap-south-1, sa-east-1, eu-central-1, ap-northeast-2, ap-southeast-2)

Unlike other networks/demos, there is no fee balance you need to setup or faucet to visit. Instead the network entrypoints throttle inclusion (just like they would if you had a monthly plan with a game). For now, we rate limit. In the future, think monthly plans that permit some amount of load per day or week. In an era of blockchain abundance, there are many applications that don’t need to fight for inclusion.

It all starts when you first submit a transaction: Instruction::Generate(). When the transaction is processed, it generates a random character using the VRF output emitted from notarizing the block in which your transaction is included. This includes things like your look, name, and even powers.

General decryption by generating an arbitrary message (like a block being finalized in a given view)




Next, you enter matchmaking. After so many views (or when full), the lobby will pair all players again using the VRF to deter anyone from auto-matching with another account they control.



Then, battle. There are 15 rounds of fighting (unless someone is KO’d before then). When battling, you encrypt your move to the round expiry view and when that view passes can submit a settle transaction that decrypts each player’s move (or defaults to no move if not present or invalid). The move is then scaled again by the VRF to ensure your attacks aren’t too sure of a thing.


Unlike a traditional commit-reveal scheme, anyone can reveal the contents of the encrypted data as long as they have the seed it was encrypted to.

When a battle is complete, an ELO score update is computed as a function of your expected damage given (in a ratio of your ELO score to your opponent’s). The top 10 are features on the homepage.

The real magic, however, is what is happening behind the scenes to make this all possible. When you interact with battleware, you only trust the validators (any data served to your browser is both authenticated via storage and wrapped with a threshold signature).

Integrated (reliable) indexing means gone are the days of spinning up some sort of polling infrastructure. Nodes push valid data and the backend processes it (wherever it came from) if it is wrapped with a valid threshold signature. This is particularly challenging because we can’t actually generate a signature over any root until after execution (because we only know the VRF after verify).



All state served entails exoware generating a proof on-the-fly and wrapping it again with a threshold signature around the root the proof was generated from. To ensure execution is fast enough, we concurrently process decryptions. To save bandwidth, we compute a filtered stream for each listener comprised of dynamically generated multi-proofs (thing of it like concatenated single proofs to represent a collection of items over a sparse range). When switching to the explore, switches back to the firehose.



To ensure there are always games to play, we run bots behind the scenes. Think of it like a tutorial to learn the game, they move randomly.

In our second blog post, we discuss the topic of “Seeds” and “Views” and how it is feasible to construct an application that doesn’t rely on the safety/correctness guarantees of infrastructure.

A few years ago, Moxie Marlinspike wrote about his first impressions of web3. Moxie examined how close we were to a web as rich as web3 but decentralized. “We should accept the premise that people will not run their own servers by designing systems that can distribute trust without having to distribute infrastructure.” We’re getting close now.

“Embedded application/game”

Plan
- Moxie web3 blog: https://moxie.org/2022/01/07/web3-first-impressions.html
    - “We should accept the premise that people will not run their own servers by designing systems that can distribute trust without having to distribute infrastructure.”
- VRF + Binding Timelock Encryption (How to “Make a Move” in a game?)
    - character generation/battle move strength is chosen by VRF
    - image: user targets some seed in the future and encodes, submits seed to settle, VRF determines move strength in block hwere in cluded
- Stream to Browser with multi-proofs/state proofs with threshold signatures via exoware
    - Chain Construction (Aggregation) → generate threshold signature over execution results (can’t be computed during verify because need VRF output of said block to compute results)
- custom execution to pre-decrypt settlement ciphertext to increase throughput
- fees enforced through network gateways rather than onchain
    - each builder decides what they are willing to pack in their block and as long as under resource usage, its ok
- Next: state sync + reconfiguration
