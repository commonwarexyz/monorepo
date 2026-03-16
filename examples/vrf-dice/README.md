# commonware-vrf-dice

Provably fair dice, coin flip and lottery demo using [commonware-cryptography](https://docs.rs/commonware-cryptography): Ed25519 + SHA-256 VRF.

## Run

From the **monorepo root** (after adding this crate to the workspace):

```bash
cargo run -p commonware-vrf-dice
```

Server listens on `0.0.0.0:8080` (override with `PORT`). API only (no static UI).

## API

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/register` | Register a player (optional `player_name`). Returns `public_key`, `short_id`. |
| POST | `/api/roll` | Roll dice / flip coin / lottery. Body: `player_name?`, `client_seed?`, `player_public_key?`, `game_mode?` (`dice`, `coin`, `lottery`). |
| POST | `/api/verify` | Verify a past roll: `round`, `player_name`, `client_seed`, `claimed_proof`, `claimed_result`, `game_mode?`. |
| GET | `/api/history` | Last 100 rolls (bounded; older rolls are evicted). |
| GET | `/api/info` | Server public key and stats (`total_rolls` is all-time). |
| GET | `/api/leaderboard` | Per-player stats over the last 100 rolls. |
| GET | `/api/proof/:round` | Proof and record for a round. |
| GET | `/api/ping` | Health check. |

## VRF

Randomness is derived from the server’s Ed25519 signature over a deterministic message (round, player, client seed, game mode). The SHA-256 hash of that signature is used to compute the result (dice 1–6, coin 0–1, lottery 1–100). Anyone can verify using the server’s public key and the returned proof.

## License

Dual-licensed under Apache-2.0 and MIT (same as the Commonware monorepo).
