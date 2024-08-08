# p2p

## Disclaimer

`p2p` is **ALPHA** software and is not yet recommended for production use. Developers should expect breaking changes and occasional instability.

## Features

* no TLS
* chacha20-poly1305 encryption
* native message chunking
* arbitrary crypto identities
* peer discovery using ordered bit vectors
* fully-connected peers
* configurable rate limiting for each message type
* metrics via prometheus
* message prioritization across channels
* multi-plexing over a single connection

## Components 

### Dialer

### Listener

### Tracker

### Spawner

### Peer

### Router