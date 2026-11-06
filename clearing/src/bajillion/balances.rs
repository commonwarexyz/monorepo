//! Stores of the finalized balances an operator serves.

use super::{Amount, Epoch, Error};
use commonware_cryptography::PublicKey;
use std::{
    collections::HashMap,
    future::{Future, ready},
};

/// Durable store of the finalized balances of the accounts an operator or shard serves.
///
/// It holds each account's balance as of the last close the operator wrote, and that close's epoch.
/// The operator reads balances only for the accounts an epoch involves, so the store may hold far
/// more accounts than the operator ever keeps in memory.
///
/// Both operations are atomic. A [get](Self::get) reads the epoch and the balances together, so the
/// balances are as of the epoch it returns. A [put](Self::put) applies only if the store still
/// holds the close of the epoch the operator passes as `previous`, checked together with its
/// writes, and then records the new epoch and every balance at once. Otherwise it writes nothing.
/// Once another writer, or a second process on the same store, has moved the epoch, the operator's
/// put fails and changes nothing.
///
/// A SQL store implements each operation as one transaction. Get reads the epoch row and the
/// balances in one snapshot transaction, so both see the same commit. Put updates the epoch row
/// where it still holds `previous`, requires one changed row, and writes the balances.
///
/// A store whose transactions cannot hold one close writes each new balance as a version tagged
/// with the new epoch and an identifier unique to the put. The conditional epoch write is the
/// commit point, and it also records the identifier as that epoch's committed put, keeping one such
/// record per epoch. Get returns the committed epoch with each account's newest version from a
/// committed put, so the versions of a put that fails its condition never become visible. Such a
/// store writes a zero balance as a zero version, since deleting the account would expose an older
/// one.
///
/// ```text
///             version (e, id) of each balance
///   put(e)    -----x-------x-------x-------x----------------------------------> time
///                                          ^ epoch previous -> e, only if it is still previous
///   get       <- as of previous ---------->|<- as of e ->
/// ```
///
/// A put consumes the store and returns it only on success, so an error or a dropped future drops
/// it.
pub trait Balances<P: PublicKey, A: Amount>: Send + Sync + Sized + 'static {
    /// The type of error returned when reading or writing balances.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Returns the epoch of the last close the store holds, and the balance of each of `accounts`
    /// as of that close, in order, with zero for an account without one.
    fn get(
        &self,
        accounts: &[P],
    ) -> impl Future<Output = Result<(Epoch, Vec<A>), Self::Error>> + Send;

    /// Records `epoch` and writes `balances` in one atomic step if the store holds the close of
    /// `previous`, and otherwise fails without writing.
    ///
    /// `balances` holds the new balance of every account the close changes, and may be empty. An
    /// account given a zero balance then has none. The operator stores closes in increasing epoch
    /// order and may skip epochs. A put that fails, or whose future is dropped, may or may not have
    /// committed, and the restarted operator reads which with get.
    fn put(
        self,
        previous: Epoch,
        epoch: Epoch,
        balances: &[(P, A)],
    ) -> impl Future<Output = Result<Self, Self::Error>> + Send;
}

/// [Balances] held in memory.
///
/// Nothing survives the process, so it suits tests and deployments that rebuild their balances
/// when they restart. A put that does not find the store at `previous` returns
/// [Error::WrongEpoch].
#[derive(Clone, Debug)]
pub struct MemoryBalances<P: PublicKey, A: Amount> {
    epoch: Epoch,
    balances: HashMap<P, A>,
}

impl<P: PublicKey, A: Amount> MemoryBalances<P, A> {
    /// Returns a store before the first close, holding no balance.
    pub fn new() -> Self {
        Self {
            epoch: 0,
            balances: HashMap::new(),
        }
    }
}

impl<P: PublicKey, A: Amount> Default for MemoryBalances<P, A> {
    fn default() -> Self {
        Self::new()
    }
}

impl<P: PublicKey, A: Amount> Balances<P, A> for MemoryBalances<P, A> {
    type Error = Error;

    fn get(
        &self,
        accounts: &[P],
    ) -> impl Future<Output = Result<(Epoch, Vec<A>), Self::Error>> + Send {
        let balances = accounts
            .iter()
            .map(|account| self.balances.get(account).copied().unwrap_or(A::ZERO))
            .collect();
        ready(Ok((self.epoch, balances)))
    }

    fn put(
        mut self,
        previous: Epoch,
        epoch: Epoch,
        balances: &[(P, A)],
    ) -> impl Future<Output = Result<Self, Self::Error>> + Send {
        if previous != self.epoch {
            return ready(Err(Error::WrongEpoch {
                expected: previous,
                found: self.epoch,
            }));
        }
        for (account, balance) in balances {
            if *balance == A::ZERO {
                self.balances.remove(account);
            } else {
                self.balances.insert(account.clone(), *balance);
            }
        }
        self.epoch = epoch;
        ready(Ok(self))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{
        Signer as _,
        ed25519::{PrivateKey, PublicKey},
    };
    use commonware_runtime::{Runner as _, deterministic};

    #[test]
    fn test_memory_balances_store_closes() {
        deterministic::Runner::default().start(|_| async move {
            let [alice, bob] = [0, 1].map(|seed| PrivateKey::from_seed(seed).public_key());
            let store = MemoryBalances::<PublicKey, u64>::new();
            assert_eq!(store.get(&[]).await.unwrap(), (0, Vec::new()));

            // A close writes balances and records its epoch.
            let store = store
                .put(0, 1, &[(alice.clone(), 5), (bob.clone(), 3)])
                .await
                .unwrap();
            assert_eq!(
                store.get(&[bob.clone(), alice.clone()]).await.unwrap(),
                (1, vec![3, 5])
            );

            // A zero balance removes the account, and other balances stay.
            let store = store.put(1, 2, &[(alice.clone(), 0)]).await.unwrap();
            assert_eq!(
                store.get(&[alice.clone(), bob.clone()]).await.unwrap(),
                (2, vec![0, 3])
            );

            // A put that does not find the store at its previous epoch writes nothing.
            let copy = store.clone();
            assert!(matches!(
                copy.put(1, 3, &[(bob.clone(), 9)]).await,
                Err(Error::WrongEpoch {
                    expected: 1,
                    found: 2
                })
            ));
            assert_eq!(store.get(&[bob]).await.unwrap(), (2, vec![3]));
        });
    }
}
