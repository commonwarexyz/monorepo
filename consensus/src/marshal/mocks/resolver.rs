use commonware_utils::sync::Mutex;
use std::{sync::Arc};
use commonware_utils::{hash_map, HashMap};

#[derive(Clone)]
pub struct Resolver<K, V> {
    data: Arc<Mutex<HashMap<K, V>>>,
}

impl<K: Eq + std::hash::Hash, V> Default for Resolver<K, V> {
    fn default() -> Self {
        Self {
            data: Arc::new(Mutex::new(hash_map::new())),
        }
    }
}

impl<K: Eq + std::hash::Hash, V: Clone> Resolver<K, V> {
    pub fn get(&self, key: K) -> V {
        self.data.lock().get(&key).unwrap().clone()
    }

    pub fn put(&self, key: K, value: V) {
        self.data.lock().insert(key, value);
    }
}
