# commonware-chat 

[![Crates.io](https://img.shields.io/crates/v/commonware-chat.svg)](https://crates.io/crates/commonware-chat)

Send encrypted messages to a group of friends using [commonware-p2p](https://crates.io/crates/commonware-p2p).

## Usage (4 Friends)

### Friend 1 (Bootstrapper)

```sh
cargo run -- --me=1@3001 --friends=1,2,3,4
```

### Friend 2

```sh
cargo run -- --me=2@3002 --friends=1,2,3,4 --bootstrappers=1@127.0.0.1:3001 
```

### Friend 3

```sh
cargo run -- --me=3@3003 --friends=1,2,3,4 --bootstrappers=1@127.0.0.1:3001 
```

### Friend 4 (Different Friend as Bootstrapper)

```sh
cargo run -- --me=4@3004 --friends=1,2,3,4 --bootstrappers=3@127.0.0.1:3003
```

### Not Friend (Blocked)

```sh
cargo run -- --me=5@3005 --friends=1,2,3,4,5 --bootstrappers=1@127.0.0.1:3001 
```