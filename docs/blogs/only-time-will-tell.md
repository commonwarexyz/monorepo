# Binding Timelock Encryption: Only Time Will Tell

As your parents insisted when you were growing up, good things come to those that wait. It turns out recent advances in cryptography have proven them right.

When competing head-to-head, revealing your move before your opponent gives them an obvious advantage. If I know you're playing rock, I'll play paper. Whether it's rock-paper-scissors or a keyword auction for search results, competitive applications need to hide submissions until everyone has committed. That's why they typically run on centralized infrastructure where moves can be blinded until resolution.

Blockchains don't yet offer this "temporal privacy". Transactions are public the moment they hit the mempool. Look no further than the meteoric rise of MEV bots that monitor mempools, frontrun trades, and sandwich transactions to see the value of this information leakage.

What if blockchains could run fair competitions?

## The Missing Primitive: Binding Timelock Encryption (BTLE)

Enter [Practical Timelock Encryption (TLE)](https://eprint.iacr.org/2023/189). TLE lets you encrypt data to a future moment (specifically, when validators generate a threshold signature over a known message). Once that signature exists, anyone can use it as a decryption key to reveal the encrypted data. Simply put, if you know the static public key of some threshold set and you know a message it will sign at some point, you can encrypt data that can be decrypted when a signature is generated over that message.

It turns out we already have such a signature generation mechanism in the [Commonware Library](https://github.com/commonwarexyz/monorepo): [threshold-simplex](https://docs.rs/commonware-consensus/latest/commonware_consensus/threshold_simplex/index.html)'s VRF. At each view (every ~200ms on a global network), validators produce a threshold signature over the view number (a message that can be known ahead of time by anyone looking for a timelock encryption target).

TLE, a standalone cryptographic primitive, however, lacks the ability to enforce commitments to encrypted data. Nothing in the TLE scheme prevents a user from sharing different encrypted data to different people or encrypting updated data if they change their mind. Embedded into a blockchain, TLE commitments become "Binding Timelock Encryption" (BTLE). Submit an encrypted move before the end of a contest, and you can't back out or change your mind (your move is stored in state and can't be changed). Anyone possessing the VRF output associated with the end of the contest can decrypt the committed ciphertext.

With BTLE, blockchains can finally offer temporal privacy. Good things (or fair contests onchain), as your parents said, come to those that wait (for timelock decryption).

## BATTLEWARE: Proving BTLE is Practical

To demonstrate how to use Binding Timelock Encryption, we built [BATTLEWARE](https://battleware.xyz). BATTLEWARE is an onchain game where players duel each other to climb a global leaderboard (sorted by ELO score). If you've played Pokémon, you'll feel right at home.

<TODO: add battleware game screenshot>
_Figure 1: A battle between two trainers on BATTLEWARE. The opponent (DEVOTE RITUAL) has locked their move for this round but we can't see it yet._

It all starts when you submit a transaction to generate your "creature". The same signature generation mechanism used to power BTLE decryption doubles as the VRF used to randomly generate your creature's appearance, name, and moves.

<TODO: add creature generation screenshot>

Once generated, you enter the arena for matchmaking. Again using the same VRF, we randomly pair you with some other player (making it a bit more difficult to bias your matches to certain opponents).

<TODO: add matchmaking screenshot>

Once in a battle, you have 15 rounds to defeat your opponent. During each round, both players submit encrypted moves to the view at which the battle will be resolved. Once the view is reached, either player can submit the VRF output to the chain to decrypt both players' moves and resolve the round. If a player has won, the battle resolves and each player's ELO score is updated. If not, the battle continues to the next round.

<TODO: add move submission>

To make things performant enough, we perform parallel decryption of moves during execution using a custom-built execution environment.

The entire implementation—all 11.2k lines of it—is [open source](https://github.com/commonwarexyz/battleware). The code is still rough around the edges, but we've got 77% test coverage and consider it an excellent opportunity to become a Commonware contributor.

## Securing Access

Instead of trusting some API to provide access to state, we leverage threshold signatures and MMRs to provide authenticated access to the frontend. What does this mean?

After each block is executed, we apply state changes and events to MMRs. We then using consensus::aggregation to generate a threshold signature over the roots of each.

<TODO: add MMR screenshot>

Once a threshold signature is generated, nodes then push these state and events to Exoware. On-the-fly, Exoware generates Multi-Proofs over the events that matter to a particular websocket subscriber.

<TODO: Add multi-proof screenshot>

Updates are then sent to your frontend where you both verify the threshold signature attesting to some root was signed by a quorum of nodes and that there exists a valid proof of your events in the root.

## Wrapping Things Up

At Commonware, [we believe that the best onchain experiences will develop a sustained edge through specialization](TODO). Whether it be a battle game, a trading application, a social network, or something only you know how to build, building a blockchain around a product provides differentiated capability that can't be bolted on to existing blockchains.

We will (finally) have capacity to onboard our next Commonware design partner on October 1st. If you want to collaborate on a blockchain application that doesn't feel like one, reach out now (our next slot opens in 2026).