# Epocher

Continuously simulate epochs with a small local network.

- Each epoch is 100 blocks
- 4 validators participate (keys 1, 2, 3, 4)
- Each block contains: parent digest, block height, and a random u64

## Usage

To run this example, you must first install Rust.

Open four terminals and start one bootstrapper, then three joiners.

### Validator 1 (Bootstrapper)
```bash
cargo run -p commonware-epocher --release -- --me 1@3001
```

### Validator 2
```bash
cargo run -p commonware-epocher --release -- --me 2@3002 --bootstrappers 1@127.0.0.1:3001
```

### Validator 3
```bash
cargo run -p commonware-epocher --release -- --me 3@3003 --bootstrappers 1@127.0.0.1:3001
```

### Validator 4
```bash
cargo run -p commonware-epocher --release -- --me 4@3004 --bootstrappers 1@127.0.0.1:3001
```

You should see logs indicating finalized blocks (e.g., `finalized-delivered-to-app`) and epoch transitions.

## Options

- `--me KEY@PORT`: required. KEY must be 1, 2, 3, or 4. Binds to `127.0.0.1:PORT` and derives the node key from `KEY`.
- `--bootstrappers KEY@HOST:PORT[,KEY@HOST:PORT...]`: optional. One or more known peers to initially connect to.

