# Binding Timelock Encryption: Only Time Will Tell

As your parents insisted when you were growing up, good things come to those that wait. It turns out recent advances in cryptography have proven them right.

When competing head-to-head, revealing your move before your opponent gives them an obvious advantage. If I know you're playing rock, I'll play paper. Whether it's rock-paper-scissors or a keyword auction for search results, competitive applications need to hide submissions until everyone has committed. That's why they typically run on centralized infrastructure where moves can be blinded until resolution.

Blockchains don't yet offer this "temporal privacy". Transactions are public the moment they hit the mempool. Look no further than the meteoric rise of MEV bots that monitor mempools, frontrun trades, and sandwich transactions to see the value of this information leakage.

What if blockchains could run fair competitions?

## The Missing Primitive: Binding Timelock Encryption (BTLE)

Enter [Practical Timelock Encryption (TLE)](https://eprint.iacr.org/2023/189). TLE lets you encrypt data to a future moment—specifically, when validators generate a threshold signature over a known message (like a view number in [threshold-simplex](https://docs.rs/commonware-consensus/latest/commonware_consensus/threshold_simplex/index.html)). Once that signature exists, anyone can use it as a decryption key to reveal the encrypted data. Simply put, if you know the static public key of some threshold set and you know a message it will sign at some point, you can encrypt data that can be decrypted when a signature is generated over that message.

Take rock-paper-scissors. Both players encrypt their moves to the same future time, say 60 seconds away. Neither can see the other's choice (the moves are encrypted and can be shared publicly). When that time arrives and validators sign some message over the payload chosen as the encryption target, their threshold signature becomes the decryption key. No further coordination needed. If it sounds like magic, that's because it is.

TLE, a standalone cryptographic primitive, however, lacks the ability to enforce commitments to encrypted data. Nothing in the TLE scheme prevents a user from sharing different encrypted data to different people or encrypting updated data if they change their mind.

This is where blockchains come in. When TLE is embedded onchain, it becomes "Binding Timelock Encryption" (BTLE). Your encrypted move gets written to state and can't be changed. You're committed. When the target block arrives, anyone with the VRF output can decrypt your move onchain.

This eliminates the "free option" problem of commit-reveal schemes. In a sealed-bid auction where Player 1 bids 10, Player 2 bids 20, and Player 3 bids 30, Player 3 can't wait to see others reveal then refuse to show their overpriced bid. With BTLE, all bids decrypt automatically when the auction ends. No selective disclosure. No strategic withholding.

With BTLE, blockchains can finally offer temporal privacy. Good things, as your parents said, come to those that wait.

## BATTLEWARE: Proving BTLE is Practical

To demonstrate just how useful BTLE is, we built [BATTLEWARE](https://battleware.xyz). BATTLEWARE is an onchain game where players duel each other for bragging rights on a global leaderboard. If you've played Pokémon, you'll feel right at home.


<TODO: add battleware game screenshot>

It all starts when you submit your first transaction to generate your "creature". The same VRF used to power BTLE decryption is also used to randomly generate your creature's appearance, name, and moves.

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