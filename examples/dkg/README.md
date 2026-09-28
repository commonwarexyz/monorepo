# commonware-dkg

[![Crates.io](https://img.shields.io/crates/v/commonware-dkg.svg)](https://crates.io/crates/commonware-dkg)

Generate and reshare a threshold secret over an epoched log.

Committees rotate deterministically: for epoch `E`, the committee starts at
offset `E % participants.len()` and takes `committee_size` consecutive
participants with wraparound.

The application state is one `any::unordered::fixed` QMDB with one fixed key,
and each non-genesis block writes its height to that key. Genesis carries the
epoch-0 `EpochInfo`.

## Usage

Generate the node configurations:

```sh
cargo run --bin commonware-dkg -- setup --node-dir ./data --peers 6 --committee-size 4 --base-port 3000
```

`setup` creates every `validator-*` directory with node and network config,
then prints `mprocs` commands to run the epoch-0 bootstrap players and the
validators. Use `mprocs` or run its enclosed commands in separate terminals.

`bootstrap` runs the one-shot glue DKG among the epoch-0 players, which
generates the initial threshold secret and the genesis `EpochInfo`. Only the
epoch-0 players run it because only they receive shares. To bootstrap:

1. Start `bootstrap` concurrently for every epoch-0 player.
2. When a player completes, it writes `genesis.json` into its own directory and
   every non-player validator directory, then logs `bootstrap complete, serving
   peers until stopped`. It keeps serving so players that have not completed
   can catch up from it.
3. Once every player has logged that line, stop every `bootstrap` and start the
   validators.

`validator` starts from the genesis written by `bootstrap` and runs the
application chain, stateful QMDB, continuous reshare, DKG orchestrator, and DKG
probe.

## Storage

Each validator owns one directory under the configured data directory:

```text
data/
  validator-0/
    node.json
    network.json
    genesis.json
    runtime/
```

`node.json` contains the node's Ed25519 signing key and listen/dial addresses.
`network.json` contains the ordered participant list, fixed committee size, and
peer dial addresses. `genesis.json` contains the epoch-0 `EpochInfo`. `runtime/`
is the Commonware storage root for all blob partitions used by that node.

Private DKG material lives in two partitions of `runtime/`. `bootstrap` keeps
its share, dealer seed, and received dealings in `bootstrap-secrets`. When the
ceremony completes, `bootstrap` copies only the node's epoch-0 share, if it has
one, into `secrets`. `validator` uses `secrets` for that share and for the
shares, dealer seeds, and received dealings of every reshare, and erases
`bootstrap-secrets` when it starts. The bootstrap and the first reshare both
store epoch-0 seeds and dealings, so they must not share a partition.

## State Sync

Start a late joiner with `validator --state-sync`. A late joiner is a node that
joins after launch and whose key is in a future committee. It uses `dkg::probe`
to fetch a recent finalized block and that epoch's public material from peers,
saves the block as its sync floor, and state-syncs QMDB from it instead of
replaying from genesis. Nodes that launch the network run without the flag.

The flag only matters until a node saves a sync floor or starts from genesis.
After that, the node follows its storage: it resumes an unfinished sync or
continues from its local blocks, so keeping the flag on restarts is harmless.

A player that misses its private dealings cannot recover them by syncing. The
ceremony completes without it and publicly reveals its share.
