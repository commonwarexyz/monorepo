# Browser P2P native service

This standalone crate owns pairing invitation state and optionally embeds the Bun production
bundle from `../browser/dist`. It intentionally has no networking implementation.

The intended integration is:

1. A WebSocket admission implementation parses the session ID and capability and calls
   `PairingStore::reserve`. Store the returned reservation in the accepted connection's permit.
2. The authenticated handshake produces the remote Ed25519 public-key bytes.
3. Call `PairingReservation::consume_and_bind`. Forward the returned `PeerAdmission` to the
   application's lookup connection-attachment seam.
4. If admission or the handshake fails or is canceled, drop the reservation. Its RAII guard
   releases only the reservation it owns.

No P2P attachment interface is specified here. The application must connect `PeerAdmission` to
the real authenticated lookup API available at integration time.

To embed frontend assets, first run `bun run build` in `../browser`, then compile this crate. If
`dist/` is absent, the crate still compiles and `EmbeddedAssets::is_embedded()` returns false.

