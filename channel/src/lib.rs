//! State channel protocol with block-height timeouts.
//!
//! A channel is a dispute resolution layer around any deterministic
//! program (cartridge). Players execute the cartridge locally, exchange
//! signed actions peer-to-peer, and only involve the chain (court) if
//! there's a dispute.
//!
//! # Time model
//!
//! Block height IS time. No wall-clock, no NTP. Simplex finalizes
//! blocks at a known rate. Timeouts are measured in finalized blocks.
//! When N blocks pass without a player's action, they're timed out.
//!
//! # Dispute types
//!
//! 1. **Timeout** — player didn't act within N blocks. Court checks
//!    the action log against block heights. No proof needed, just
//!    the signed log.
//!
//! 2. **Invalid action** — player submitted an action the cartridge
//!    rejects. Court replays the log (or verifies a WIM proof) and
//!    slashes the cheater.
//!
//! 3. **Conflicting history** — players disagree on what happened.
//!    Both submit signed logs. The hash chain reveals the fork point.
//!    Whoever signed the forking action is the liar.
//!
//! # Normal flow (no disputes)
//!
//! ```text
//! Alice          Bob           Court
//!   |-- action -->|              |
//!   |<-- action --|              |
//!   |-- action -->|              |
//!   |   ...       |              |
//!   |-- settle -->|              |
//!   |<-- settle --|              |
//!   |------------ settle ------->|  (co-signed settlement)
//! ```
//!
//! Court is only involved for the final settlement or if someone
//! disputes. The game happens entirely off-chain.

#![cfg_attr(not(any(feature = "std", test)), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use sha2::{Digest, Sha256};

/// A signed action in the channel's action log.
#[derive(Debug, Clone)]
pub struct Entry {
    /// Sequence number (monotonically increasing).
    pub seq: u64,
    /// Block height at which this action was finalized.
    pub height: u64,
    /// The player who acted (seat index).
    pub seat: u8,
    /// The action payload (cartridge-specific).
    pub payload: Vec<u8>,
    /// SHA-256 hash of the previous entry (chain link).
    pub prev_hash: [u8; 32],
    /// Player's signature over (seq, height, seat, payload, prev_hash).
    pub signature: [u8; 64],
}

impl Entry {
    /// Compute the hash of this entry for chaining.
    pub fn hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(self.seq.to_le_bytes());
        h.update(self.height.to_le_bytes());
        h.update([self.seat]);
        h.update((self.payload.len() as u32).to_le_bytes());
        h.update(&self.payload);
        h.update(self.prev_hash);
        h.update(self.signature);
        let result = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }

    /// The data that gets signed: everything except the signature itself.
    pub fn signing_data(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.seq.to_le_bytes());
        data.extend_from_slice(&self.height.to_le_bytes());
        data.push(self.seat);
        data.extend_from_slice(&(self.payload.len() as u32).to_le_bytes());
        data.extend_from_slice(&self.payload);
        data.extend_from_slice(&self.prev_hash);
        data
    }
}

/// Channel state: the ordered log of signed actions.
#[derive(Debug, Clone)]
pub struct Channel {
    /// Hash of the agreed-upon cartridge (program both parties run).
    pub cartridge_hash: [u8; 32],
    /// Number of players.
    pub num_players: u8,
    /// Timeout in blocks.
    pub timeout_blocks: u64,
    /// The action log.
    pub log: Vec<Entry>,
}

/// Result of a dispute check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// No dispute. Channel is in good standing.
    Ok,
    /// Player timed out. Their seat index.
    Timeout(u8),
    /// Hash chain is broken at the given sequence number.
    BrokenChain(u64),
    /// Duplicate sequence number.
    DuplicateSeq(u64),
    /// Sequence numbers not monotonically increasing.
    OutOfOrder { expected: u64, got: u64 },
}

impl Channel {
    /// Create a new channel.
    pub fn new(cartridge_hash: [u8; 32], num_players: u8, timeout_blocks: u64) -> Self {
        Self {
            cartridge_hash,
            num_players,
            timeout_blocks,
            log: Vec::new(),
        }
    }

    /// Append an entry to the log.
    pub fn push(&mut self, entry: Entry) {
        self.log.push(entry);
    }

    /// The hash of the latest entry (or zeros if empty).
    pub fn tip_hash(&self) -> [u8; 32] {
        self.log.last().map_or([0u8; 32], |e| e.hash())
    }

    /// Current block height (height of last entry, or 0).
    pub fn tip_height(&self) -> u64 {
        self.log.last().map_or(0, |e| e.height)
    }

    /// Validate the hash chain integrity.
    pub fn validate_chain(&self) -> Verdict {
        let mut prev_hash = [0u8; 32];
        let mut expected_seq = 0u64;

        for entry in &self.log {
            if entry.seq != expected_seq {
                return Verdict::OutOfOrder {
                    expected: expected_seq,
                    got: entry.seq,
                };
            }
            if entry.prev_hash != prev_hash {
                return Verdict::BrokenChain(entry.seq);
            }
            prev_hash = entry.hash();
            expected_seq += 1;
        }

        Verdict::Ok
    }

    /// Check if any player has timed out at the given block height.
    ///
    /// Returns the seat of the player who should have acted but didn't,
    /// or None if everyone is within the timeout window.
    pub fn check_timeout(
        &self,
        current_height: u64,
        next_to_act: u8,
    ) -> Option<u8> {
        let last_height = self.tip_height();

        if current_height > last_height + self.timeout_blocks {
            Some(next_to_act)
        } else {
            None
        }
    }

    /// Find the fork point between two logs.
    ///
    /// Returns the sequence number where the logs diverge, or None
    /// if they agree on all shared entries.
    pub fn find_fork(log_a: &[Entry], log_b: &[Entry]) -> Option<u64> {
        for (a, b) in log_a.iter().zip(log_b.iter()) {
            if a.seq != b.seq || a.hash() != b.hash() {
                return Some(a.seq.min(b.seq));
            }
        }

        // If one log is longer, the fork is at the divergence point
        let min_len = log_a.len().min(log_b.len());
        if log_a.len() != log_b.len() {
            return Some(min_len as u64);
        }

        None
    }

    /// Number of entries in the log.
    pub fn len(&self) -> usize {
        self.log.len()
    }

    /// Whether the log is empty.
    pub fn is_empty(&self) -> bool {
        self.log.is_empty()
    }
}

/// A settlement: both players agree on the final state.
#[derive(Debug, Clone)]
pub struct Settlement {
    /// The channel's cartridge hash.
    pub cartridge_hash: [u8; 32],
    /// Final balances per seat.
    pub balances: Vec<u64>,
    /// Hash of the final entry in the agreed log.
    pub final_hash: [u8; 32],
    /// Number of actions in the agreed log.
    pub num_actions: u64,
    /// Co-signatures from all players.
    pub signatures: Vec<[u8; 64]>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(seq: u64, height: u64, seat: u8, prev_hash: [u8; 32]) -> Entry {
        Entry {
            seq,
            height,
            seat,
            payload: vec![seat, (seq & 0xFF) as u8],
            prev_hash,
            signature: [0u8; 64],
        }
    }

    #[test]
    fn test_hash_chain_valid() {
        let mut ch = Channel::new([1u8; 32], 2, 10);

        let e0 = make_entry(0, 100, 0, [0u8; 32]);
        let h0 = e0.hash();
        ch.push(e0);

        let e1 = make_entry(1, 101, 1, h0);
        let h1 = e1.hash();
        ch.push(e1);

        let e2 = make_entry(2, 102, 0, h1);
        ch.push(e2);

        assert_eq!(ch.validate_chain(), Verdict::Ok);
    }

    #[test]
    fn test_hash_chain_broken() {
        let mut ch = Channel::new([1u8; 32], 2, 10);

        let e0 = make_entry(0, 100, 0, [0u8; 32]);
        ch.push(e0);

        // Wrong prev_hash
        let e1 = make_entry(1, 101, 1, [0xFF; 32]);
        ch.push(e1);

        assert_eq!(ch.validate_chain(), Verdict::BrokenChain(1));
    }

    #[test]
    fn test_sequence_out_of_order() {
        let mut ch = Channel::new([1u8; 32], 2, 10);

        let e0 = make_entry(0, 100, 0, [0u8; 32]);
        let h0 = e0.hash();
        ch.push(e0);

        // Skipped seq 1
        let e2 = make_entry(2, 101, 1, h0);
        ch.push(e2);

        assert_eq!(
            ch.validate_chain(),
            Verdict::OutOfOrder { expected: 1, got: 2 }
        );
    }

    #[test]
    fn test_timeout_detected() {
        let ch = Channel::new([1u8; 32], 2, 10);
        // Empty log, tip_height = 0, timeout = 10
        // At height 11, player 0 has timed out
        assert_eq!(ch.check_timeout(11, 0), Some(0));
        assert_eq!(ch.check_timeout(10, 0), None);
    }

    #[test]
    fn test_timeout_with_actions() {
        let mut ch = Channel::new([1u8; 32], 2, 10);

        let e0 = make_entry(0, 100, 0, [0u8; 32]);
        ch.push(e0);

        // Player 1 hasn't acted. At height 111 (100 + 10 + 1), timeout.
        assert_eq!(ch.check_timeout(111, 1), Some(1));
        assert_eq!(ch.check_timeout(110, 1), None);
    }

    #[test]
    fn test_find_fork_same_logs() {
        let e0 = make_entry(0, 100, 0, [0u8; 32]);
        let h0 = e0.hash();
        let e1 = make_entry(1, 101, 1, h0);

        assert_eq!(Channel::find_fork(&[e0.clone(), e1.clone()], &[e0, e1]), None);
    }

    #[test]
    fn test_find_fork_divergent() {
        let e0 = make_entry(0, 100, 0, [0u8; 32]);
        let h0 = e0.hash();

        let e1a = make_entry(1, 101, 0, h0); // Alice's version
        let e1b = make_entry(1, 101, 1, h0); // Bob's version (different seat)

        let fork = Channel::find_fork(&[e0.clone(), e1a], &[e0, e1b]);
        assert_eq!(fork, Some(1));
    }

    #[test]
    fn test_find_fork_different_length() {
        let e0 = make_entry(0, 100, 0, [0u8; 32]);
        let h0 = e0.hash();
        let e1 = make_entry(1, 101, 1, h0);

        // Alice has 2 entries, Bob has 1
        let fork = Channel::find_fork(&[e0.clone(), e1], &[e0]);
        assert_eq!(fork, Some(1));
    }

    #[test]
    fn test_settlement() {
        let settlement = Settlement {
            cartridge_hash: [1u8; 32],
            balances: vec![600, 400],
            final_hash: [2u8; 32],
            num_actions: 15,
            signatures: vec![[0u8; 64], [0u8; 64]],
        };

        assert_eq!(settlement.balances.len(), 2);
        assert_eq!(settlement.num_actions, 15);
    }
}
