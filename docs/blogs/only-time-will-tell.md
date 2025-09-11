# Binding Timelock Encryption: Only Time Will Tell

As your parents insisted when you were growing up, good things come to those that wait. It turns out recent advances in cryptography have proven them right.

When competing head-to-head, publicly revealing your move to an opponent (before they've done the same) offers an obvious advantage. This applies the same to a game of rock-paper-scissors as it does an keyword auction on your search result. If I know you are playing rock, I'll play paper. Applications incorporating games or contests thus blind submissions until some time period has elapsed to ensure fairness.

Blockchains, unlike the centralized infrastructure typically used for building such applications, don't yet offer this same "temporal privacy". Transactions submitted onchain are public the moment they hit the mempool. To see the value of this information leakage, look no further than the meteoric rise of MEV bots that monitor mempools, frontrun trades, and sandwich transactions.

What if blockchains could be used for fair games and contests?

## The Missing Primitive: Binding Timelock Encryption (BTLE)

Enter [Practical Timelock Encryption (TLE)](https://eprint.iacr.org/2023/189). TLE enables anyone to encrypt some data to a specific time in the future, typically a known index when some VRF output is revealed. When published, any observer can use this VRF output to decrypt the ciphertext provided by the user.

Think rock-paper-scissors, again. Two players can encrypt their moves for the same point in the future. Prior to that point, neither player knows what the other player chose (so sharing their move at any time prior to decryption offers no advantage). Once that point is reached, both players can decrypt their moves simultaneously using the corresponding VRF output (no collaboration with the other required).

TLE, a standalone cryptographic primitive, lacks the ability to enforce commitments to encrypted data. Nothing prevents a user from sharing different encrypted data to different people or encrypting updated data if they change their mind. What we really need is "Binding Timelock Encryption" (BTLE).

Embedded into a blockchain, TLE commitments become binding (BTLE). Submit an encrypted ciphertext before the end of a contest, and you can't back out or change your mind. Anyone possessing the VRF output associated with the end of the contest can decrypt the ciphertext and reveal the commitments (no interaction required).

Unlike commit-reveal schemes, TLE removes the "free option" any participant has to hide their reveal (if, say, revealing a commitment isn't in their favor). Consider an auction with 3 people bidding. Player 1 commits to 10, Player 2 commits to 20, Player 3 commits to 30. Player 3 waits for Player 1 and Player 2 to reveal their bids, and then determines not to reveal because 30 overvalued the item.

With BTLE, blockchains can finally offer temporal privacy. Good things (or fair contests onchain), as your parents said, come to those that wait.

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