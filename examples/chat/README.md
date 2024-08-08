# chat 

[![Crates.io](https://img.shields.io/crates/v/commonware-chat.svg)](https://crates.io/crates/commonware-chat)

Send encrypted messages to a group of friends using [commonware-p2p](https://crates.io/crates/commonware-p2p).

## Usage

### Person 1 (Bootstrapper)

```
cargo run -- --me=1@3001 --allowed_keys=1,2,3,4
```

### Person 2

```
cargo run -- --me=2@3002 --allowed_keys=1,2,3,4 --bootstrappers=1@127.0.0.1:3001 
```

### Person 3

```
cargo run -- --me=3@3003 --allowed_keys=1,2,3,4 --bootstrappers=1@127.0.0.1:3001 
```

### Person 4 (Different Bootstrapper)

```
cargo run -- --me=4@3004 --allowed_keys=1,2,3,4 --bootstrappers=3@127.0.0.1:3003
```

### Person 5 (Blocked)

```
cargo run -- --me=5@3005 --allowed_keys=1,2,3,4,5 --bootstrappers=1@127.0.0.1:3001 
```