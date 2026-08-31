//! One-wallet client workflows for the clearing terminal.

mod claim;
mod custody;
mod pay;
mod receive;
mod store;
#[cfg(test)]
mod tests;
mod wallet;

pub(crate) use custody::WithdrawalOutcome;
pub(crate) use pay::PaymentOutcome;
pub(crate) use wallet::Agent;
