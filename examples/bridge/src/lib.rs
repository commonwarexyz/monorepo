//! Send succinct consensus certificates between two networks.
//!
//! This example demonstrates how to build an application that employs [commonware_consensus::threshold_simplex].
//! Whenever it is a participant's turn to build a block, they either randomly generate a 16-byte message or
//! include a succinct consensus certificate from the other network (if available). They then upload the block to an
//! `indexer` and send a digest of the block to other participants. Participants in the network will fetch the block
//! from the `indexer` and verify it contains a 16-byte message or a valid consensus certificate from the other network.
//! Once a block is finalized, all participants attempt to post the emitted succinct consensus certificate to the `indexer`.
//! Leader election is performed using the embedded VRF provided by [commonware_consensus::threshold_simplex].
//!
//! # Architecture
//!
//! ```txt
//!                                  +-----------+
//!                 +--------------->|           |<--------------+
//!                 |                |  Indexer  |               |
//!                 |   +------------+           +-----------+   |
//!                 |   |            +-----------+           |   |
//! Put(1,Block)    |   |                                    |   | Put(2,Block)
//! Put(1,Finalize) |   | Get(1,Block)       Get(2,Block)    |   | Put(2,Finalize)
//!                 |   | Get(2,Finalize)    Get(1,Finalize) |   |
//!                 |   |                                    |   |
//!                 |   v                                    v   |
//!             +---+---------+                         +--------+----+
//!             |             |                         |             |
//!             |  Network 1  |                         |  Network 2  |
//!             |             |                         |             |
//!             +-------------+                         +-------------+
//! ```
//!
//! # Persistence
//!
//! All consensus data is persisted to disk in the `storage-dir` directory. If you shutdown (whether unclean or not),
//! consensus will resume where it left off when you restart.
//!
//! # Broadcast and Backfilling
//!
//! This example demonstrates how [commonware_consensus::threshold_simplex] can minimally be used to efficiently power
//! interoperability between two networks. To simplify the example, an `indexer` is used both to distribute blocks
//! and to collect finality certificates. A production-grade implementation would likely replace the `indexer` with
//! a p2p broadcast mechanism.
//!
//! # Usage
//!
//! _To run this example, you must first install [Rust](https://www.rust-lang.org/tools/install) and [protoc](https://grpc.io/docs/protoc-installation)._
//!
//! ## Generate Shared Secrets
//!
//! _A production-grade implementation should use a DKG (and Resharing during reconfiguration). For example, you could use [commonware_cryptography::bls12381::dkg]_
//!
//! We assign shares to validators based on their order in the sorted list of participants (by public key).
//! The assignments seen below are just the indices used to derive the shares and as such do not necessarily
//! align with the share indices.
//!
//! ### Network 1
//!
//! ```sh
//! cargo run --release --bin dealer -- --seed 1 --participants 1,2,3,4
//! ```
//!
//! ```txt
//! polynomial: a4a1b4b8a3fb2c11f4dba5c6c57743554f746d2211cd519c3c980b8d8019f8fa328b97e44e19dcc6150688da5f38fbcd8e754b2a66d247e9937e35326a36415adfe606082c86bb823a63ba9a2a9c87f146f3d55d067b5f08f768e76f8ea382f2aa2a5bfcfc67656703f15fb905bc271514bfb0be0eb54becaba4743754638b7a1d9d2fbf3d4e2ea07850601f82a1d3ac
//! public: a4a1b4b8a3fb2c11f4dba5c6c57743554f746d2211cd519c3c980b8d8019f8fa328b97e44e19dcc6150688da5f38fbcd
//! share (index=0 validator=2): 000000003521e062da79bd64dc8c5e0d07f07d64c805a137153ef2e6fa5485d28026990e
//! share (index=1 validator=4): 000000016b63f2c22039b703a52e4903a00986d2ea63361d3a6ef33b00330a52d4dce155
//! share (index=2 validator=3): 000000023fa89505734c5ab4d8727e5011e17fd0fee654d1f05496f0a9660025432adc38
//! share (index=3 validator=1): 0000000325dd6e7ffd4f25c0a992d5fa671a4064594ca15836ee3a06f5ed6748cb1089b8
//! ```
//!
//! ### Network 2
//!
//! ```sh
//! cargo run --release --bin dealer -- --seed 2 --participants 5,6,7,8
//! ```
//!
//! ```txt
//! polynomial: a311e2573501053c4b0dc00b64462d5d47c787d143a5b3cfe22c16a9023b89734074356ea0ce70ab71fe2042c2e426f58ff12f093cfbe796aa417ffa938be43cfe13ac8fe8c9bc1fddddfe8de840b8372d3165aa172fe930ed6ade9501dbe2ac80e9c5debaaad3eed786c1670b3f13a03712bfe6f326e57f48bb536522c3fb0a465e95a2de83ef3159675523842ef892
//! public: a311e2573501053c4b0dc00b64462d5d47c787d143a5b3cfe22c16a9023b89734074356ea0ce70ab71fe2042c2e426f5
//! share (index=0 validator=6): 000000004dba2ad66b0bb0760cdfc1b1e51fb96fb3b6bdd8cdd451beca1fb0247b2071c0
//! share (index=1 validator=7): 000000014342ca6e1877c338e416dc67bb836c996ca78e5c99dc12e937008e810c59ba44
//! share (index=2 validator=8): 0000000255ccd5a1f8962ce3e665d75f504d27e33db466838eb38476a162a32e4e73341a
//! share (index=3 validator=5): 00000003116aa51ee1c9702ee092da9099db1347d31fa24aac5c4a680945ee2d416cdf41
//! ```
//!
//! ## Start Indexer
//!
//! The `indexer` is a simple service that uses [commonware_stream::public_key] to accept blocks and finality certificates from a known set of participants outside
//! of the p2p instances maintained by each network.
//!
//! ```sh
//! cargo run --release --bin indexer -- --me 0@3000 --participants 1,2,3,4,5,6,7,8 --networks a4a1b4b8a3fb2c11f4dba5c6c57743554f746d2211cd519c3c980b8d8019f8fa328b97e44e19dcc6150688da5f38fbcd,a311e2573501053c4b0dc00b64462d5d47c787d143a5b3cfe22c16a9023b89734074356ea0ce70ab71fe2042c2e426f5
//! ```
//!
//! ## Start Validators
//!
//! Each network has an `identity` (the group polynomial generated above) and each validator has a `share` that can be used to create partial signatures that can be verified on said `identity`. The `other-identity` is the public
//! key (constant term) of the other network's group polynomial. This value would remain static across a reshare (not implemented in this demo).
//!
//! ### Network 1 (Run at Least 3 to Make Progress)
//!
//! #### Participant 1 (Bootstrapper)
//!
//! ```sh
//! cargo run --release --bin validator -- --me 1@3001 --participants 1,2,3,4 --storage-dir /tmp/commonware-bridge/1 --indexer 0@127.0.0.1:3000 --identity a4a1b4b8a3fb2c11f4dba5c6c57743554f746d2211cd519c3c980b8d8019f8fa328b97e44e19dcc6150688da5f38fbcd8e754b2a66d247e9937e35326a36415adfe606082c86bb823a63ba9a2a9c87f146f3d55d067b5f08f768e76f8ea382f2aa2a5bfcfc67656703f15fb905bc271514bfb0be0eb54becaba4743754638b7a1d9d2fbf3d4e2ea07850601f82a1d3ac --share 0000000325dd6e7ffd4f25c0a992d5fa671a4064594ca15836ee3a06f5ed6748cb1089b8 --other-identity a311e2573501053c4b0dc00b64462d5d47c787d143a5b3cfe22c16a9023b89734074356ea0ce70ab71fe2042c2e426f5
//! ```
//!
//! #### Participant 2
//!
//! ```sh
//! cargo run --release --bin validator -- --me 2@3002 --bootstrappers 1@127.0.0.1:3001 --participants 1,2,3,4 --storage-dir /tmp/commonware-bridge/2 --indexer 0@127.0.0.1:3000 --identity a4a1b4b8a3fb2c11f4dba5c6c57743554f746d2211cd519c3c980b8d8019f8fa328b97e44e19dcc6150688da5f38fbcd8e754b2a66d247e9937e35326a36415adfe606082c86bb823a63ba9a2a9c87f146f3d55d067b5f08f768e76f8ea382f2aa2a5bfcfc67656703f15fb905bc271514bfb0be0eb54becaba4743754638b7a1d9d2fbf3d4e2ea07850601f82a1d3ac --share 000000003521e062da79bd64dc8c5e0d07f07d64c805a137153ef2e6fa5485d28026990e --other-identity a311e2573501053c4b0dc00b64462d5d47c787d143a5b3cfe22c16a9023b89734074356ea0ce70ab71fe2042c2e426f5
//! ```
//!
//! #### Participant 3
//!
//! ```sh
//! cargo run --release --bin validator -- --me 3@3003 --bootstrappers 1@127.0.0.1:3001 --participants 1,2,3,4 --storage-dir /tmp/commonware-bridge/3 --indexer 0@127.0.0.1:3000 --identity a4a1b4b8a3fb2c11f4dba5c6c57743554f746d2211cd519c3c980b8d8019f8fa328b97e44e19dcc6150688da5f38fbcd8e754b2a66d247e9937e35326a36415adfe606082c86bb823a63ba9a2a9c87f146f3d55d067b5f08f768e76f8ea382f2aa2a5bfcfc67656703f15fb905bc271514bfb0be0eb54becaba4743754638b7a1d9d2fbf3d4e2ea07850601f82a1d3ac --share 000000023fa89505734c5ab4d8727e5011e17fd0fee654d1f05496f0a9660025432adc38 --other-identity a311e2573501053c4b0dc00b64462d5d47c787d143a5b3cfe22c16a9023b89734074356ea0ce70ab71fe2042c2e426f5
//! ```
//!
//! #### Participant 4
//!
//! ```sh
//! cargo run --release --bin validator -- --me 4@3004 --bootstrappers 1@127.0.0.1:3001 --participants 1,2,3,4 --storage-dir /tmp/commonware-bridge/4 --indexer 0@127.0.0.1:3000 --identity a4a1b4b8a3fb2c11f4dba5c6c57743554f746d2211cd519c3c980b8d8019f8fa328b97e44e19dcc6150688da5f38fbcd8e754b2a66d247e9937e35326a36415adfe606082c86bb823a63ba9a2a9c87f146f3d55d067b5f08f768e76f8ea382f2aa2a5bfcfc67656703f15fb905bc271514bfb0be0eb54becaba4743754638b7a1d9d2fbf3d4e2ea07850601f82a1d3ac --share 000000016b63f2c22039b703a52e4903a00986d2ea63361d3a6ef33b00330a52d4dce155 --other-identity a311e2573501053c4b0dc00b64462d5d47c787d143a5b3cfe22c16a9023b89734074356ea0ce70ab71fe2042c2e426f5
//! ```
//!
//! ### Network 2 (Run at Least 3 to Make Progress)
//!
//! #### Participant 5
//!
//! ```sh
//! cargo run --release --bin validator -- --me 5@3005 --participants 5,6,7,8 --storage-dir /tmp/commonware-bridge/5 --indexer 0@127.0.0.1:3000 --identity a311e2573501053c4b0dc00b64462d5d47c787d143a5b3cfe22c16a9023b89734074356ea0ce70ab71fe2042c2e426f58ff12f093cfbe796aa417ffa938be43cfe13ac8fe8c9bc1fddddfe8de840b8372d3165aa172fe930ed6ade9501dbe2ac80e9c5debaaad3eed786c1670b3f13a03712bfe6f326e57f48bb536522c3fb0a465e95a2de83ef3159675523842ef892 --share 00000003116aa51ee1c9702ee092da9099db1347d31fa24aac5c4a680945ee2d416cdf41 --other-identity a4a1b4b8a3fb2c11f4dba5c6c57743554f746d2211cd519c3c980b8d8019f8fa328b97e44e19dcc6150688da5f38fbcd
//! ```
//!
//! #### Participant 6
//!
//! ```sh
//! cargo run --release --bin validator -- --me 6@3006 --bootstrappers 5@127.0.0.1:3005 --participants 5,6,7,8 --storage-dir /tmp/commonware-bridge/6 --indexer 0@127.0.0.1:3000 --identity a311e2573501053c4b0dc00b64462d5d47c787d143a5b3cfe22c16a9023b89734074356ea0ce70ab71fe2042c2e426f58ff12f093cfbe796aa417ffa938be43cfe13ac8fe8c9bc1fddddfe8de840b8372d3165aa172fe930ed6ade9501dbe2ac80e9c5debaaad3eed786c1670b3f13a03712bfe6f326e57f48bb536522c3fb0a465e95a2de83ef3159675523842ef892 --share 000000004dba2ad66b0bb0760cdfc1b1e51fb96fb3b6bdd8cdd451beca1fb0247b2071c0 --other-identity a4a1b4b8a3fb2c11f4dba5c6c57743554f746d2211cd519c3c980b8d8019f8fa328b97e44e19dcc6150688da5f38fbcd
//! ```
//!
//! #### Participant 7
//!
//! ```sh
//! cargo run --release --bin validator -- --me 7@3007 --bootstrappers 5@127.0.0.1:3005 --participants 5,6,7,8 --storage-dir /tmp/commonware-bridge/7 --indexer 0@127.0.0.1:3000 --identity a311e2573501053c4b0dc00b64462d5d47c787d143a5b3cfe22c16a9023b89734074356ea0ce70ab71fe2042c2e426f58ff12f093cfbe796aa417ffa938be43cfe13ac8fe8c9bc1fddddfe8de840b8372d3165aa172fe930ed6ade9501dbe2ac80e9c5debaaad3eed786c1670b3f13a03712bfe6f326e57f48bb536522c3fb0a465e95a2de83ef3159675523842ef892 --share 000000014342ca6e1877c338e416dc67bb836c996ca78e5c99dc12e937008e810c59ba44 --other-identity a4a1b4b8a3fb2c11f4dba5c6c57743554f746d2211cd519c3c980b8d8019f8fa328b97e44e19dcc6150688da5f38fbcd
//! ```
//!
//! #### Participant 8
//!
//! ```sh
//! cargo run --release --bin validator -- --me 8@3007 --bootstrappers 5@127.0.0.1:3005 --participants 5,6,7,8 --storage-dir /tmp/commonware-bridge/8 --indexer 0@127.0.0.1:3000 --identity a311e2573501053c4b0dc00b64462d5d47c787d143a5b3cfe22c16a9023b89734074356ea0ce70ab71fe2042c2e426f58ff12f093cfbe796aa417ffa938be43cfe13ac8fe8c9bc1fddddfe8de840b8372d3165aa172fe930ed6ade9501dbe2ac80e9c5debaaad3eed786c1670b3f13a03712bfe6f326e57f48bb536522c3fb0a465e95a2de83ef3159675523842ef892 --share 0000000255ccd5a1f8962ce3e665d75f504d27e33db466838eb38476a162a32e4e73341a --other-identity a4a1b4b8a3fb2c11f4dba5c6c57743554f746d2211cd519c3c980b8d8019f8fa328b97e44e19dcc6150688da5f38fbcd
//! ```

#[doc(hidden)]
pub mod wire {
    include!(concat!(env!("OUT_DIR"), "/wire.rs"));
}
#[doc(hidden)]
pub mod application;
#[doc(hidden)]
pub const APPLICATION_NAMESPACE: &[u8] = b"_COMMONWARE_BRIDGE";
#[doc(hidden)]
pub const P2P_SUFFIX: &[u8] = b"_P2P";
#[doc(hidden)]
pub const CONSENSUS_SUFFIX: &[u8] = b"_CONSENSUS";
#[doc(hidden)]
pub const INDEXER_NAMESPACE: &[u8] = b"_COMMONWARE_INDEXER";
