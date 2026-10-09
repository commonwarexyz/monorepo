// These fixtures compile against the real tokio and futures channels so the lint sees the
// crates that define them.

#![allow(dead_code)]

use futures_channel::{mpsc as futures_mpsc, oneshot as futures_oneshot};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    rc::Rc,
    sync::{Arc, Mutex, Weak},
};
use tokio::sync::{OwnedSemaphorePermit, mpsc, oneshot};

/// Owns a channel endpoint through a field.
struct Mailbox {
    sender: mpsc::Sender<u8>,
}

/// Owns a channel endpoint through an enum variant.
enum Slot {
    Empty,
    Waiting(oneshot::Sender<u8>),
}

/// A recursive type that owns a channel endpoint.
struct Node {
    children: Vec<Node>,
    waiter: Option<oneshot::Sender<()>>,
}

/// A recursive type without channel endpoints.
struct Tree {
    children: Vec<Tree>,
}

struct Registry {
    waiters: HashMap<u64, oneshot::Sender<()>>,
}

struct Fields {
    // Elements that own endpoints directly or through fields, variants, tuples, arrays, nested
    // collections, type arguments, and shared owners, also when the collection sits inside a
    // wrapper.
    mailboxes: HashMap<u64, Mailbox>,
    slots: HashMap<u64, Slot>,
    nodes: HashSet<Node>,
    pairs: HashMap<u64, (u8, futures_oneshot::Receiver<u8>)>,
    batches: HashMap<u64, Vec<[mpsc::UnboundedSender<u8>; 2]>>,
    nested: HashMap<u64, HashMap<u64, futures_mpsc::UnboundedReceiver<u8>>>,
    permits: HashMap<u64, OwnedSemaphorePermit>,
    shared: Arc<Mutex<HashMap<u64, futures_mpsc::Sender<u8>>>>,
    optional: Option<hashbrown::HashMap<u64, mpsc::Receiver<u8>>>,
    arcs: HashMap<u64, Arc<oneshot::Sender<()>>>,
    rcs: HashMap<u64, Rc<Mailbox>>,

    // Ordered collections, weak handles, elements without endpoints, and borrowed collections
    // are not flagged.
    ordered: BTreeMap<u64, oneshot::Sender<()>>,
    weak: HashMap<u64, Weak<oneshot::Sender<()>>>,
    weak_registry: Weak<Mutex<HashMap<u64, oneshot::Sender<()>>>>,
    trees: HashMap<u64, Tree>,
    borrowed: &'static HashMap<u64, oneshot::Sender<()>>,

    // An expectation keeps a hash collection when no task can be waiting on its elements.
    #[cfg_attr(
        dylint_lib = "hash_order",
        expect(hash_drop, reason = "every sender is removed before the map drops")
    )]
    expected: HashMap<u64, oneshot::Sender<()>>,
}

fn main() {
    // A `let` that creates a collection of endpoints.
    let created: HashMap<u64, oneshot::Sender<()>> = HashMap::new();
    let mut inferred = HashMap::new();
    inferred.insert(0u64, oneshot::channel::<()>().0);
    let _defaulted: HashMap<u64, Mailbox> = Default::default();
    let _collected: HashMap<u64, oneshot::Sender<()>> = Vec::new().into_iter().collect();
    let _converted = HashMap::from([(0u64, oneshot::channel::<()>().0)]);
    let _cloned = HashMap::<u64, mpsc::Sender<u8>>::new().clone();

    // A `let` that moves, borrows, or fills a field with a collection is not flagged.
    let moved = created;
    let _borrowed = &moved;
    let _taken = std::mem::take(&mut inferred);
    let _ordered: BTreeMap<u64, oneshot::Sender<()>> = BTreeMap::new();
    let _registry = Registry {
        waiters: HashMap::new(),
    };

    // An expectation keeps a hash collection when no task can be waiting on its elements.
    #[cfg_attr(
        dylint_lib = "hash_order",
        expect(hash_drop, reason = "every sender is removed before the map drops")
    )]
    let _expected: HashMap<u64, oneshot::Sender<()>> = HashMap::new();
}
