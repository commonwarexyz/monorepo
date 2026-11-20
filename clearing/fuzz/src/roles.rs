//! The reference roles of the crate's own tests (`clearing/tests/bajillion/roles`), built from its
//! public API alone and included here as they are.

#[allow(dead_code)]
#[path = "../../tests/bajillion/roles/ledger.rs"]
pub mod ledger;
#[allow(dead_code)]
#[path = "../../tests/bajillion/roles/operator.rs"]
pub mod operator;
#[allow(dead_code)]
#[path = "../../tests/bajillion/roles/receiver.rs"]
pub mod receiver;
#[allow(dead_code)]
#[path = "../../tests/bajillion/roles/sender.rs"]
pub mod sender;
#[allow(dead_code)]
#[path = "../../tests/bajillion/roles/validator.rs"]
pub mod validator;
