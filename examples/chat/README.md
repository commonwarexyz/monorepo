# commonware-chat 

[![Crates.io](https://img.shields.io/crates/v/commonware-chat.svg)](https://crates.io/crates/commonware-chat)
[![Docs.rs](https://docs.rs/commonware-chat/badge.svg)](https://docs.rs/commonware-chat)

Send encrypted messages to a group of friends using [commonware-cryptography::ed25519](https://docs.rs/commonware-cryptography/latest/commonware_cryptography/ed25519/index.html)
and [commonware-p2p::authenticated](https://docs.rs/commonware-p2p/latest/commonware_p2p/authenticated/index.html).

## Offline Friends

`commonware-chat` only sends messages to connected friends. If a friend is offline at the time a message is sent,
`commonware-p2p::authenticated` will drop the message. You can confirm you are connected to all your friends by checking the value
of `p2p_connections` in the "Metrics Panel" in the right corner of the window. This metric should be equal to
`count(friends)- 1` (you don't connect to yourself).

## Synchonized Friends

`commonware-p2p::authenticated` requires all friends to have the same set of friends for friend discovery to work
correctly. If you do not synchronize friends, you may be able to form connections between specific friends but may
not be able to form connections with all friends. You can learn more about why
this is [here](https://docs.rs/commonware-p2p/latest/commonware_p2p/authenticated/index.html#discovery). Other
dialects of `commonware-p2p` may not have this requirement.

## Usage (4 Friends)

### Friend 1 (Bootstrapper)

```sh
cargo run --release -- --me=1@3001 --friends=1,2,3,4
```

### Friend 2

```sh
cargo run --release -- --me=2@3002 --friends=1,2,3,4 --bootstrappers=1@127.0.0.1:3001 
```

### Friend 3

```sh
cargo run --release -- --me=3@3003 --friends=1,2,3,4 --bootstrappers=1@127.0.0.1:3001 
```

### Friend 4 (Different Friend as Bootstrapper)

```sh
cargo run --release -- --me=4@3004 --friends=1,2,3,4 --bootstrappers=3@127.0.0.1:3003
```

### Not Friend (Blocked)

```sh
cargo run --release -- --me=5@3005 --friends=1,2,3,4,5 --bootstrappers=1@127.0.0.1:3001 
```