use crate::{Application, View};
use commonware_cryptography::{PublicKey, Scheme};
use prometheus_client::registry::Registry;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Duration,
};

pub struct Config<C: Scheme, A: Application> {
    pub crypto: C,
    pub application: A,

    pub registry: Arc<Mutex<Registry>>,

    pub namespace: String,

    pub leader_timeout: Duration,
    pub notarization_timeout: Duration,

    /// Validators to use for each range of views. Any view without
    /// an explicit view will use the next smallest view.
    pub validators: BTreeMap<View, Vec<PublicKey>>,
}
