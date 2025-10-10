use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

#[derive(Clone)]
pub struct Resolver<K, V> {
    data: Arc<Mutex<HashMap<K, V>>>,
}

impl<K: Eq + std::hash::Hash, V> Default for Resolver<K, V> {
    fn default() -> Self {
        Self {
            data: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl<K: Eq + std::hash::Hash, V: Clone> Resolver<K, V> {
    pub fn get(&self, key: K) -> V {
        self.data
            .lock()
            .expect("mock resolver mutex should not be poisoned on get")
            .get(&key)
            .expect("key should exist in mock resolver")
            .clone()
    }

    pub fn put(&self, key: K, value: V) {
        self.data
            .lock()
            .expect("mock resolver mutex should not be poisoned on put")
            .insert(key, value);
    }
}
