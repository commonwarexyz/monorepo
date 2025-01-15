# commonware-bridge

[![Crates.io](https://img.shields.io/crates/v/commonware-bridge.svg)](https://crates.io/crates/commonware-bridge)

Send succinct consensus certificates between two networks.

# Usage

_To run this example, you must first install [Rust](https://www.rust-lang.org/tools/install) and [protoc](https://grpc.io/docs/protoc-installation)._

## Generate Shared Secrets

### Network 1

```bash
cargo run --release --bin dealer -- --seed 1 --participants 1,2,3,4
```

```txt
polynomial: a4a1b4b8a3fb2c11f4dba5c6c57743554f746d2211cd519c3c980b8d8019f8fa328b97e44e19dcc6150688da5f38fbcd8e754b2a66d247e9937e35326a36415adfe606082c86bb823a63ba9a2a9c87f146f3d55d067b5f08f768e76f8ea382f2aa2a5bfcfc67656703f15fb905bc271514bfb0be0eb54becaba4743754638b7a1d9d2fbf3d4e2ea07850601f82a1d3ac
public: a4a1b4b8a3fb2c11f4dba5c6c57743554f746d2211cd519c3c980b8d8019f8fa328b97e44e19dcc6150688da5f38fbcd
share (index=0 validator=2): 000000003521e062da79bd64dc8c5e0d07f07d64c805a137153ef2e6fa5485d28026990e
share (index=1 validator=4): 000000016b63f2c22039b703a52e4903a00986d2ea63361d3a6ef33b00330a52d4dce155
share (index=2 validator=3): 000000023fa89505734c5ab4d8727e5011e17fd0fee654d1f05496f0a9660025432adc38
share (index=3 validator=1): 0000000325dd6e7ffd4f25c0a992d5fa671a4064594ca15836ee3a06f5ed6748cb1089b8
```

### Network 2

```bash
cargo run --release --bin dealer -- --seed 2 --participants 5,6,7,8
```

```txt
polynomial: a311e2573501053c4b0dc00b64462d5d47c787d143a5b3cfe22c16a9023b89734074356ea0ce70ab71fe2042c2e426f58ff12f093cfbe796aa417ffa938be43cfe13ac8fe8c9bc1fddddfe8de840b8372d3165aa172fe930ed6ade9501dbe2ac80e9c5debaaad3eed786c1670b3f13a03712bfe6f326e57f48bb536522c3fb0a465e95a2de83ef3159675523842ef892
public: a311e2573501053c4b0dc00b64462d5d47c787d143a5b3cfe22c16a9023b89734074356ea0ce70ab71fe2042c2e426f5
share (index=0 validator=6): 000000004dba2ad66b0bb0760cdfc1b1e51fb96fb3b6bdd8cdd451beca1fb0247b2071c0
share (index=1 validator=7): 000000014342ca6e1877c338e416dc67bb836c996ca78e5c99dc12e937008e810c59ba44
share (index=2 validator=8): 0000000255ccd5a1f8962ce3e665d75f504d27e33db466838eb38476a162a32e4e73341a
share (index=3 validator=5): 00000003116aa51ee1c9702ee092da9099db1347d31fa24aac5c4a680945ee2d416cdf41
```

## Start Indexer

```bash
cargo run --release --bin indexer -- --me 0@3000 --participants 1,2,3,4,5,6,7,8 --networks a4a1b4b8a3fb2c11f4dba5c6c57743554f746d2211cd519c3c980b8d8019f8fa328b97e44e19dcc6150688da5f38fbcd,a311e2573501053c4b0dc00b64462d5d47c787d143a5b3cfe22c16a9023b89734074356ea0ce70ab71fe2042c2e426f5
```

## Start Validators

### Network 1 (Run at Least 3 to Make Progress)

#### Participant 1 (Bootstrapper)

```bash
cargo run --release --bin validator -- --me 1@3001 --participants 1,2,3,4 --storage-dir /tmp/commonware-bridge/1 --indexer 0@127.0.0.1:3000 --identity a4a1b4b8a3fb2c11f4dba5c6c57743554f746d2211cd519c3c980b8d8019f8fa328b97e44e19dcc6150688da5f38fbcd8e754b2a66d247e9937e35326a36415adfe606082c86bb823a63ba9a2a9c87f146f3d55d067b5f08f768e76f8ea382f2aa2a5bfcfc67656703f15fb905bc271514bfb0be0eb54becaba4743754638b7a1d9d2fbf3d4e2ea07850601f82a1d3ac --share 0000000325dd6e7ffd4f25c0a992d5fa671a4064594ca15836ee3a06f5ed6748cb1089b8 --other-identity a311e2573501053c4b0dc00b64462d5d47c787d143a5b3cfe22c16a9023b89734074356ea0ce70ab71fe2042c2e426f5
```

#### Participant 2

```bash
cargo run --release --bin validator -- --me 2@3002 --bootstrappers 1@127.0.0.1:3001 --participants 1,2,3,4 --storage-dir /tmp/commonware-bridge/2 --indexer 0@127.0.0.1:3000 --identity a4a1b4b8a3fb2c11f4dba5c6c57743554f746d2211cd519c3c980b8d8019f8fa328b97e44e19dcc6150688da5f38fbcd8e754b2a66d247e9937e35326a36415adfe606082c86bb823a63ba9a2a9c87f146f3d55d067b5f08f768e76f8ea382f2aa2a5bfcfc67656703f15fb905bc271514bfb0be0eb54becaba4743754638b7a1d9d2fbf3d4e2ea07850601f82a1d3ac --share 000000003521e062da79bd64dc8c5e0d07f07d64c805a137153ef2e6fa5485d28026990e --other-identity a311e2573501053c4b0dc00b64462d5d47c787d143a5b3cfe22c16a9023b89734074356ea0ce70ab71fe2042c2e426f5
```

#### Participant 3

```bash
cargo run --release --bin validator -- --me 3@3003 --bootstrappers 1@127.0.0.1:3001 --participants 1,2,3,4 --storage-dir /tmp/commonware-bridge/3 --indexer 0@127.0.0.1:3000 --identity a4a1b4b8a3fb2c11f4dba5c6c57743554f746d2211cd519c3c980b8d8019f8fa328b97e44e19dcc6150688da5f38fbcd8e754b2a66d247e9937e35326a36415adfe606082c86bb823a63ba9a2a9c87f146f3d55d067b5f08f768e76f8ea382f2aa2a5bfcfc67656703f15fb905bc271514bfb0be0eb54becaba4743754638b7a1d9d2fbf3d4e2ea07850601f82a1d3ac --share 000000023fa89505734c5ab4d8727e5011e17fd0fee654d1f05496f0a9660025432adc38 --other-identity a311e2573501053c4b0dc00b64462d5d47c787d143a5b3cfe22c16a9023b89734074356ea0ce70ab71fe2042c2e426f5
```

#### Participant 4

```bash
cargo run --release --bin validator -- --me 4@3004 --bootstrappers 1@127.0.0.1:3001 --participants 1,2,3,4 --storage-dir /tmp/commonware-bridge/4 --indexer 0@127.0.0.1:3000 --identity a4a1b4b8a3fb2c11f4dba5c6c57743554f746d2211cd519c3c980b8d8019f8fa328b97e44e19dcc6150688da5f38fbcd8e754b2a66d247e9937e35326a36415adfe606082c86bb823a63ba9a2a9c87f146f3d55d067b5f08f768e76f8ea382f2aa2a5bfcfc67656703f15fb905bc271514bfb0be0eb54becaba4743754638b7a1d9d2fbf3d4e2ea07850601f82a1d3ac --share 000000016b63f2c22039b703a52e4903a00986d2ea63361d3a6ef33b00330a52d4dce155 --other-identity a311e2573501053c4b0dc00b64462d5d47c787d143a5b3cfe22c16a9023b89734074356ea0ce70ab71fe2042c2e426f5
```

### Network 2 (Run at Least 3 to Make Progress)

#### Participant 5

```bash
cargo run --release --bin validator -- --me 5@3005 --participants 5,6,7,8 --storage-dir /tmp/commonware-bridge/5 --indexer 0@127.0.0.1:3000 --identity a311e2573501053c4b0dc00b64462d5d47c787d143a5b3cfe22c16a9023b89734074356ea0ce70ab71fe2042c2e426f58ff12f093cfbe796aa417ffa938be43cfe13ac8fe8c9bc1fddddfe8de840b8372d3165aa172fe930ed6ade9501dbe2ac80e9c5debaaad3eed786c1670b3f13a03712bfe6f326e57f48bb536522c3fb0a465e95a2de83ef3159675523842ef892 --share 00000003116aa51ee1c9702ee092da9099db1347d31fa24aac5c4a680945ee2d416cdf41 --other-identity a4a1b4b8a3fb2c11f4dba5c6c57743554f746d2211cd519c3c980b8d8019f8fa328b97e44e19dcc6150688da5f38fbcd
```

#### Participant 6

```bash
cargo run --release --bin validator -- --me 6@3006 --bootstrappers 5@127.0.0.1:3005 --participants 5,6,7,8 --storage-dir /tmp/commonware-bridge/6 --indexer 0@127.0.0.1:3000 --identity a311e2573501053c4b0dc00b64462d5d47c787d143a5b3cfe22c16a9023b89734074356ea0ce70ab71fe2042c2e426f58ff12f093cfbe796aa417ffa938be43cfe13ac8fe8c9bc1fddddfe8de840b8372d3165aa172fe930ed6ade9501dbe2ac80e9c5debaaad3eed786c1670b3f13a03712bfe6f326e57f48bb536522c3fb0a465e95a2de83ef3159675523842ef892 --share 000000004dba2ad66b0bb0760cdfc1b1e51fb96fb3b6bdd8cdd451beca1fb0247b2071c0 --other-identity a4a1b4b8a3fb2c11f4dba5c6c57743554f746d2211cd519c3c980b8d8019f8fa328b97e44e19dcc6150688da5f38fbcd
```

#### Participant 7

```bash
cargo run --release --bin validator -- --me 7@3007 --bootstrappers 5@127.0.0.1:3005 --participants 5,6,7,8 --storage-dir /tmp/commonware-bridge/7 --indexer 0@127.0.0.1:3000 --identity a311e2573501053c4b0dc00b64462d5d47c787d143a5b3cfe22c16a9023b89734074356ea0ce70ab71fe2042c2e426f58ff12f093cfbe796aa417ffa938be43cfe13ac8fe8c9bc1fddddfe8de840b8372d3165aa172fe930ed6ade9501dbe2ac80e9c5debaaad3eed786c1670b3f13a03712bfe6f326e57f48bb536522c3fb0a465e95a2de83ef3159675523842ef892 --share 000000014342ca6e1877c338e416dc67bb836c996ca78e5c99dc12e937008e810c59ba44 --other-identity a4a1b4b8a3fb2c11f4dba5c6c57743554f746d2211cd519c3c980b8d8019f8fa328b97e44e19dcc6150688da5f38fbcd
```

#### Participant 8

```bash
cargo run --release --bin validator -- --me 8@3008 --bootstrappers 5@127.0.0.1:3005 --participants 5,6,7,8 --storage-dir /tmp/commonware-bridge/8 --indexer 0@127.0.0.1:3000 --identity a311e2573501053c4b0dc00b64462d5d47c787d143a5b3cfe22c16a9023b89734074356ea0ce70ab71fe2042c2e426f58ff12f093cfbe796aa417ffa938be43cfe13ac8fe8c9bc1fddddfe8de840b8372d3165aa172fe930ed6ade9501dbe2ac80e9c5debaaad3eed786c1670b3f13a03712bfe6f326e57f48bb536522c3fb0a465e95a2de83ef3159675523842ef892 --share 0000000255ccd5a1f8962ce3e665d75f504d27e33db466838eb38476a162a32e4e73341a --other-identity a4a1b4b8a3fb2c11f4dba5c6c57743554f746d2211cd519c3c980b8d8019f8fa328b97e44e19dcc6150688da5f38fbcd
```