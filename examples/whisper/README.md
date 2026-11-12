# commonware-whisper

[![Crates.io](https://img.shields.io/crates/v/commonware-whisper.svg)](https://crates.io/crates/commonware-whisper)

Send encrypted messages directly to another browser using the browser runtime of [commonware-runtime](https://docs.rs/commonware-runtime)
and [commonware-stream](https://docs.rs/commonware-stream).

Every page has a contact: one string that names its public key and where it can be reached. Two pages connect over
WebRTC once each dials the contact of the other. The users pass the contacts along in either order, and no server
carries the contacts or the messages. The pages authenticate the keys in the contacts before exchanging messages.

## Reaching the Other Page

The pages connect directly. On its own, a page knows only the addresses of its device. To be reached from another
network, it asks the STUN server named in `index.html` for its public address. No message passes through that server.
With the list of servers emptied, a page contacts no server and reaches only pages on the same device or local network.

A page cannot accept a connection from a page it knows nothing about, so both pages dial. The first to dial waits for
the other. Chrome stops sending to a page that has not answered for about 15 seconds, and a NAT soon forgets the path
the page opened through it. Two pages on different networks should therefore dial within a few seconds of each other.

Some networks, such as those of many mobile carriers, give a device a different public address for every destination.
Pages behind them often cannot connect directly.

## Trusting the Contacts

The pages authenticate the keys named in the contacts they dialed, so pass the contacts over a channel you trust.
Whoever can replace a contact on its way can connect to the page that dials it in place of the page it came from.
Anyone who reads a contact also learns the addresses it lists for the page.

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

1. In each page, copy the contact and pass it to the other page.
2. In each page, enter the contact of the other page and select **Dial**.

Each page then shows the public key the other proved and any message either sends. A contact connects one pair of
pages, so reload both pages to start another session.
