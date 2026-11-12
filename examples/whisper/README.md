# commonware-whisper

[![Crates.io](https://img.shields.io/crates/v/commonware-whisper.svg)](https://crates.io/crates/commonware-whisper)

Send encrypted messages directly to another browser using the browser runtime of [commonware-runtime](https://docs.rs/commonware-runtime)
and [commonware-stream](https://docs.rs/commonware-stream).

Two pages connect over WebRTC after their users pass each other one string. The first page creates an invite, and the
second answers it with a reply. No server carries the strings or the messages. Each string names its page's public key,
and the pages authenticate those keys before exchanging messages.

## Reaching the Other Page

The pages connect directly. On its own, a page knows only the addresses of its device. To be reached from another
network, it asks the STUN server named in `index.html` for its public address. No message passes through that server.
With the list of servers emptied, a page contacts no server and reaches only pages on the same device or local network.

Some networks, such as those of many mobile carriers, give a device a different public address for every destination.
Pages behind them often cannot connect directly.

## Trusting the Strings

The pages authenticate the keys named in the strings they were given, so pass the strings over a channel you trust. An
invite connects to whoever answers it. Whoever can replace both strings can connect to each page in place of the other.
Anyone who reads a string also learns the addresses it lists for the page.

## Usage

_To run this example, you must first install [Rust](https://www.rust-lang.org/tools/install) and [wasm-pack](https://github.com/drager/wasm-pack)._

### Build

```sh
wasm-pack build --target web
```

_On macOS, Apple's Clang cannot compile for WebAssembly. Install LLVM (`brew install llvm`) and prefix the command with
`CC_wasm32_unknown_unknown=$(brew --prefix llvm)/bin/clang AR_wasm32_unknown_unknown=$(brew --prefix llvm)/bin/llvm-ar`._

### Serve

```sh
python3 -m http.server 8080
```

### Connect

Open [http://localhost:8080](http://localhost:8080) in two tabs. Two people on different networks can each build and
serve the page themselves.

1. In the first page, select **Create invite** and pass the invite to the second page.
2. In the second page, submit the invite and pass the reply back to the first page.
3. In the first page, submit the reply.

Each page then shows the public key the other proved and any message either sends.
