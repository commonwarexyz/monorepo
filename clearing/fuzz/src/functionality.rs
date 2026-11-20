//! The clearing functionality of Figure 1 of the Bajillion paper, over user indices and exact
//! integers.

use crate::Table;
use commonware_clearing::bajillion::Epoch;
use std::collections::{BTreeMap, VecDeque};

/// A requirement of the functionality that an input does not meet. The functionality then answers
/// with the paper's bottom and keeps its state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bottom(pub &'static str);

/// Returns a table of zeros for `users` users.
pub fn zeros(users: usize) -> Table {
    vec![vec![0; users]; users]
}

/// Returns the entry of `epoch` in `tables`, or zero.
pub fn entry(
    tables: &BTreeMap<Epoch, Table>,
    epoch: Epoch,
    sender: usize,
    receiver: usize,
) -> u128 {
    tables
        .get(&epoch)
        .map_or(0, |table| table[sender][receiver])
}

/// The clearing functionality of the paper's Figure 1.
///
/// Every method is one of its interfaces and follows the figure line by line. Epochs start at one,
/// and every balance starts at zero.
pub struct Functionality {
    /// Whether the operator is corrupt, and which users are.
    pub operator: bool,
    pub corrupt: Vec<bool>,
    /// The finalized balances.
    pub bal: Vec<u128>,
    /// The current epoch. Every epoch before it is finalized.
    pub cur: Epoch,
    /// The queued deposits and forced withdrawals, oldest first, and how many of each the close of
    /// the current epoch must process.
    pub deposits: VecDeque<(usize, u128)>,
    pub forced: VecDeque<(usize, u128)>,
    pub min_deposits: usize,
    pub min_forced: usize,
    pub auth: BTreeMap<Epoch, Table>,
    pub pipe: BTreeMap<Epoch, Table>,
    pub carry: BTreeMap<Epoch, Table>,
    pub rcpt: BTreeMap<Epoch, Table>,
    pub wdr: BTreeMap<Epoch, Vec<u128>>,
    pub halted: bool,
}

impl Functionality {
    pub fn new(operator: bool, corrupt: Vec<bool>) -> Self {
        Self {
            operator,
            bal: vec![0; corrupt.len()],
            corrupt,
            cur: 1,
            deposits: VecDeque::new(),
            forced: VecDeque::new(),
            min_deposits: 0,
            min_forced: 0,
            auth: BTreeMap::new(),
            pipe: BTreeMap::new(),
            carry: BTreeMap::new(),
            rcpt: BTreeMap::new(),
            wdr: BTreeMap::new(),
            halted: false,
        }
    }

    pub fn users(&self) -> usize {
        self.bal.len()
    }

    /// Adds `batch` to `sender`'s row of `epoch` in `tables`.
    pub fn add(
        tables: &mut BTreeMap<Epoch, Table>,
        users: usize,
        epoch: Epoch,
        sender: usize,
        batch: &[(usize, u128)],
    ) {
        let table = tables.entry(epoch).or_insert_with(|| zeros(users));
        for (receiver, amount) in batch {
            table[sender][*receiver] += amount;
        }
    }

    /// Returns what `account` asked to withdraw softly in `epoch`.
    pub fn wdr(&self, epoch: Epoch, account: usize) -> u128 {
        self.wdr.get(&epoch).map_or(0, |amounts| amounts[account])
    }

    /// The live balance of `account`: its finalized balance less what it authorized in the
    /// current epoch.
    pub fn live(&self, account: usize) -> u128 {
        let paid: u128 = (0..self.users())
            .map(|receiver| entry(&self.auth, self.cur, account, receiver))
            .sum();
        self.bal[account]
            .checked_sub(paid)
            .expect("an honest operator authorizes within the balance")
    }

    /// `Send`. Returns the `Received` outputs as receiver and amount, or `None` if nothing
    /// happens.
    pub fn send(
        &mut self,
        sender: usize,
        batch: &[(usize, u128)],
        epoch: Epoch,
        pipe: bool,
    ) -> Option<Vec<(usize, u128)>> {
        let users = self.users();
        let distinct = batch
            .iter()
            .enumerate()
            .all(|(position, (receiver, _))| batch[..position].iter().all(|(r, _)| r != receiver));
        if self.halted || batch.is_empty() || !distinct {
            return None;
        }
        if batch.iter().any(|(_, amount)| *amount == 0) {
            return None;
        }
        let cur = self.cur;
        let honest = !self.corrupt[sender];
        if !self.operator {
            // An honest sender never goes back to an epoch before one it has already paid in.
            let later = self
                .auth
                .range(epoch.saturating_add(1)..)
                .any(|(_, table)| table[sender].iter().any(|amount| *amount != 0));
            if honest && later {
                return None;
            }
            let last = if pipe { epoch.saturating_add(1) } else { epoch };
            let total: u128 = batch.iter().map(|(_, amount)| amount).sum();
            if !(epoch..=last).contains(&cur) || total > self.live(sender) {
                return None;
            }
            Self::add(&mut self.auth, users, cur, sender, batch);
            if !honest {
                return Some(Vec::new());
            }

            // Receivers are notified at once if the sender is honest.
            let outputs = batch
                .iter()
                .map(|(receiver, _)| (*receiver, entry(&self.auth, cur, sender, *receiver)))
                .collect::<Vec<_>>();
            let rcpt = self.rcpt.entry(cur).or_insert_with(|| zeros(users));
            for (receiver, amount) in &outputs {
                rcpt[sender][*receiver] = *amount;
            }
            return Some(outputs);
        }
        if !honest {
            // A corrupt sender and a corrupt operator can produce receipts for any amount.
            return None;
        }
        match (pipe, epoch >= cur) {
            (false, true) => Self::add(&mut self.auth, users, epoch, sender, batch),
            (true, true) => Self::add(&mut self.pipe, users, epoch, sender, batch),
            // The epoch is closed, so the request can only settle in the current one.
            (true, false) if epoch.checked_add(1) == Some(cur) => {
                Self::add(&mut self.auth, users, cur, sender, batch)
            }
            _ => return None,
        }
        Some(Vec::new())
    }

    /// `Release`, from the adversary. Returns the amount of the `Received` output, if any.
    pub fn release(
        &mut self,
        sender: usize,
        receiver: usize,
        epoch: Epoch,
        amount: u128,
    ) -> Result<Option<u128>, Bottom> {
        if self.halted {
            return Err(Bottom("halted"));
        }
        if epoch < self.cur {
            return Err(Bottom("a receipt of a finalized epoch"));
        }
        if !(self.corrupt[sender] && self.operator) {
            // A state the sender signs for an epoch may include its plain and pipelined requests
            // for it, and its pipelined requests for the epoch before.
            let before = epoch
                .checked_sub(1)
                .map_or(0, |before| entry(&self.pipe, before, sender, receiver));
            let bound = entry(&self.auth, epoch, sender, receiver)
                + before
                + entry(&self.pipe, epoch, sender, receiver);
            if amount > bound {
                return Err(Bottom("a receipt beyond what the sender authorized"));
            }
        }
        if amount <= entry(&self.rcpt, epoch, sender, receiver) {
            return Ok(None);
        }
        let users = self.users();
        self.rcpt.entry(epoch).or_insert_with(|| zeros(users))[sender][receiver] = amount;
        Ok(Some(amount))
    }

    /// `Deposit`, from the ledger.
    pub fn deposit(&mut self, account: usize, amount: u128) -> Result<(), Bottom> {
        if self.halted || amount == 0 {
            return Err(Bottom("a deposit of nothing, or after a halt"));
        }
        self.deposits.push_back((account, amount));
        Ok(())
    }

    /// `ForcedWithdraw`, from the ledger.
    pub fn forced_withdraw(&mut self, account: usize, amount: u128) -> Result<(), Bottom> {
        if self.halted || amount == 0 {
            return Err(Bottom("a withdrawal of nothing, or after a halt"));
        }
        self.forced.push_back((account, amount));
        Ok(())
    }

    /// `SoftWithdraw`. Returns whether the request is recorded.
    pub fn soft_withdraw(&mut self, account: usize, amount: u128, epoch: Epoch) -> bool {
        if self.halted || amount == 0 {
            return false;
        }
        let recorded = if self.operator {
            !self.corrupt[account] && epoch >= self.cur
        } else {
            epoch == self.cur
        };
        if recorded {
            let users = self.users();
            self.wdr.entry(epoch).or_insert_with(|| vec![0; users])[account] += amount;
        }
        recorded
    }

    /// `Close`, processing the oldest `deposits` and `forced` requests. An honest operator gives
    /// nothing else. A corrupt operator gives the matrix it settles and the balances after the
    /// close. Returns the payout of each account.
    pub fn close(
        &mut self,
        deposits: usize,
        forced: usize,
        chosen: Option<(&Table, &[u128])>,
    ) -> Result<Vec<u128>, Bottom> {
        if self.halted {
            return Err(Bottom("halted"));
        }
        if !(self.min_deposits..=self.deposits.len()).contains(&deposits)
            || !(self.min_forced..=self.forced.len()).contains(&forced)
        {
            return Err(Bottom("a count outside its queue's bounds"));
        }
        let users = self.users();
        let cur = self.cur;
        let mut deposited = vec![0u128; users];
        for (account, amount) in self.deposits.iter().take(deposits) {
            deposited[*account] += amount;
        }
        let mut requested = vec![0u128; users];
        for (account, amount) in self.forced.iter().take(forced) {
            requested[*account] += amount;
        }
        let honest = self.auth.get(&cur).cloned().unwrap_or_else(|| zeros(users));
        let settled = match (self.operator, chosen) {
            (false, None) => &honest,
            (true, Some((settled, _))) => settled,
            _ => return Err(Bottom("a close of the other kind of operator")),
        };

        // A corrupt operator cannot debit an honest sender more than it authorized.
        let before = cur - 1;
        if self.operator {
            for sender in (0..users).filter(|sender| !self.corrupt[*sender]) {
                for (receiver, debit) in settled[sender].iter().enumerate() {
                    let bound = entry(&self.auth, cur, sender, receiver)
                        + entry(&self.carry, before, sender, receiver)
                        + entry(&self.pipe, cur, sender, receiver);
                    if *debit > bound {
                        return Err(Bottom("a debit beyond what an honest sender authorized"));
                    }
                }
            }
        }

        // The balance before payouts is the starting balance, plus incoming payments and
        // processed deposits, less outgoing payments.
        let mut balances = Vec::with_capacity(users);
        let mut paid = Vec::with_capacity(users);
        for account in 0..users {
            let incoming: u128 = (0..users).map(|sender| settled[sender][account]).sum();
            let outgoing: u128 = settled[account].iter().sum();
            let Some(balance) =
                (self.bal[account] + incoming + deposited[account]).checked_sub(outgoing)
            else {
                return Err(Bottom("a negative balance before payouts"));
            };
            let asked = requested[account] + self.wdr(cur, account);
            let payout = match chosen {
                None => balance.min(asked),
                Some((_, after)) => {
                    let Some(payout) = balance.checked_sub(after[account]) else {
                        return Err(Bottom("a balance above the one before payouts"));
                    };

                    // Forced withdrawals are paid in full, or the balance is emptied.
                    if payout < requested[account].min(balance) {
                        return Err(Bottom("a forced withdrawal not paid"));
                    }
                    if !self.corrupt[account] && payout > asked {
                        return Err(Bottom("a payout beyond what an honest account asked for"));
                    }
                    payout
                }
            };
            balances.push(balance - payout);
            paid.push(payout);
        }

        // The part of the pipelined requests not settled now, using the budgets that expire now
        // first, may still settle in the next epoch.
        let mut carry = zeros(users);
        for sender in (0..users).filter(|sender| !self.corrupt[*sender]) {
            for receiver in 0..users {
                let expiring = entry(&self.auth, cur, sender, receiver)
                    + entry(&self.carry, before, sender, receiver);
                let pipe = entry(&self.pipe, cur, sender, receiver);
                carry[sender][receiver] = pipe - settled[sender][receiver].saturating_sub(expiring);
            }
        }

        // A close that credits an honest receiver less than promised goes through, but halts.
        let shortchanged = (0..users).any(|sender| {
            (0..users).any(|receiver| {
                !self.corrupt[receiver]
                    && settled[sender][receiver] < entry(&self.rcpt, cur, sender, receiver)
            })
        });
        self.carry.insert(cur, carry);
        self.deposits.drain(..deposits);
        self.forced.drain(..forced);
        self.bal = balances;
        self.cur = cur + 1;
        self.min_deposits = self.deposits.len();
        self.min_forced = self.forced.len();
        self.halted = shortchanged;
        Ok(paid)
    }

    /// `Fault`, from the ledger, or from the adversary if the operator is corrupt.
    pub fn fault(&mut self, ledger: bool) -> Result<(), Bottom> {
        if self.halted {
            return Err(Bottom("halted"));
        }
        if !ledger && !self.operator {
            return Err(Bottom("a fault raised against an honest operator"));
        }
        self.halted = true;
        Ok(())
    }

    /// The `Refund` output of each account after a halt: its finalized balance and the deposits no
    /// close processed.
    pub fn refunds(&self) -> Vec<u128> {
        let mut refunds = self.bal.clone();
        for (account, amount) in &self.deposits {
            refunds[*account] += amount;
        }
        refunds
    }
}
