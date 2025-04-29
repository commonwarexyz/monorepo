use crate::index::Translator;
use commonware_runtime::Metrics;
use prometheus_client::metrics::counter::Counter;
use std::{
    collections::{hash_map::Entry, HashMap},
    mem,
};

/// The initial capacity of the hashmap. This is a guess at the number of unique keys we will
/// encounter. The hashmap will grow as needed, but this is a good starting point (covering
/// the entire [super::translator::OneCap] range).
const INITIAL_CAPACITY: usize = 256;

enum Record<V> {
    One(V),
    Many(Box<Vec<V>>),
}
/// -------- immutable iterator (newest → oldest) ---------------------------
pub struct ValueIterator<'a, V> {
    slice: &'a [V],
    idx: isize,
}

impl<'a, V> ValueIterator<'a, V> {
    #[inline]
    fn empty() -> Self {
        Self {
            slice: &[],
            idx: -1,
        }
    }
}

impl<'a, V> Iterator for ValueIterator<'a, V> {
    type Item = &'a V;
    fn next(&mut self) -> Option<Self::Item> {
        if self.idx < 0 {
            return None;
        }
        let i = self.idx as usize;
        self.idx -= 1;
        self.slice.get(i)
    }
}

/// -------- helpers on Record ---------------------------------------------
impl<V> Record<V> {
    fn iter(&self) -> ValueIterator<'_, V> {
        match self {
            Record::One(v) => ValueIterator {
                slice: std::slice::from_ref(v),
                idx: 0,
            },
            Record::Many(boxed) => ValueIterator {
                slice: boxed,
                idx: boxed.len() as isize - 1,
            },
        }
    }

    /// Ensure we have a `Vec` and return `&mut Vec<V>`.
    fn as_vec_mut(&mut self) -> &mut Vec<V> {
        match self {
            Record::Many(ref mut boxed) => boxed.as_mut(),
            Record::One(_) => {
                let old = mem::replace(self, Record::Many(Box::new(Vec::new())));
                if let Record::One(v) = old {
                    match self {
                        Record::Many(b) => {
                            b.push(v);
                            b
                        }
                        _ => unreachable!(),
                    }
                } else {
                    unreachable!()
                }
            }
        }
    }
}

/// -------- mutable iterator ----------------------------------------------
pub struct MutableIterator<'a, T: Translator, V> {
    map: *mut HashMap<T::Key, Record<V>, T>,
    key: T::Key,
    values: &'a mut Vec<V>,

    idx: usize,
    last_idx: Option<usize>,

    collisions: &'a Counter,
    pruned: &'a Counter,
}

impl<'a, T: Translator, V> Iterator for MutableIterator<'a, T, V> {
    type Item = &'a mut V;

    fn next(&mut self) -> Option<Self::Item> {
        if self.idx < 0 || self.values.is_empty() {
            return None;
        }
        let i = self.idx as usize;
        if i >= self.values.len() {
            return None;
        }

        // SAFETY: i is in‐bounds, and we hold exclusive &mut to the Vec
        let elem = unsafe { &mut *self.values.as_mut_ptr().add(i) };

        self.idx -= 1;
        self.last_idx = Some(i);
        Some(elem)
    }
}

impl<'a, T: Translator, V> MutableIterator<'a, T, V> {
    pub fn insert(&mut self, v: V) {
        self.values.push(v);
        let values_len = self.values.len();
        if values_len > 1 {
            self.collisions.inc();
        }
        if self.last_idx.is_none() {
            self.idx = values_len - 1;
        }
    }

    pub fn remove(&mut self) {
        if let Some(i) = self.last_idx.take() {
            self.values.swap_remove(i);
            self.pruned.inc();
            if i <= self.idx {
                self.idx = self.idx.saturating_sub(1);
            }
        }
    }
}

impl<'a, T: Translator, V> Drop for MutableIterator<'a, T, V> {
    fn drop(&mut self) {
        unsafe {
            let map = &mut *self.map;
            if self.values.is_empty() {
                map.remove(&self.key);
                self.pruned.inc();
                return;
            }
            if self.values.len() == 1 {
                if let Some(rec) = map.get_mut(&self.key) {
                    if let Record::Many(ref mut boxed) = rec {
                        let v = boxed.pop().unwrap();
                        *rec = Record::One(v);
                    }
                }
            }
        }
    }
}

pub struct Index<T: Translator, V> {
    translator: T,
    map: HashMap<T::Key, Record<V>, T>,
    collisions: Counter,
    keys_pruned: Counter,
}

impl<T: Translator, V> Index<T, V> {
    pub fn init(ctx: impl Metrics, tr: T) -> Self {
        let s = Self {
            translator: tr.clone(),
            map: HashMap::with_capacity_and_hasher(INITIAL_CAPACITY, tr),
            collisions: Counter::default(),
            keys_pruned: Counter::default(),
        };
        ctx.register(
            "pruned_total",
            "Number of keys pruned",
            s.keys_pruned.clone(),
        );
        ctx.register(
            "collisions_total",
            "Number of translated key collisions",
            s.collisions.clone(),
        );
        s
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.map.len()
    }
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn insert(&mut self, key: &[u8], v: V) {
        let k = self.translator.transform(key);
        match self.map.entry(k) {
            Entry::Occupied(mut occ) => {
                occ.get_mut().as_vec_mut().push(v);
                self.collisions.inc();
            }
            Entry::Vacant(vac) => {
                vac.insert(Record::One(v));
            }
        }
    }

    pub fn get_iter(&self, key: &[u8]) -> ValueIterator<V> {
        self.map
            .get(&self.translator.transform(key))
            .map(|r| r.iter())
            .unwrap_or_else(ValueIterator::empty)
    }

    fn make_iter(&mut self, key: &[u8]) -> MutableIterator<'_, T, V> {
        let k = self.translator.transform(key);
        let map_ptr = &mut self.map as *mut HashMap<T::Key, Record<V>, T>;
        let vec_ref = unsafe {
            (&mut *map_ptr)
                .entry(k)
                .or_insert_with(|| Record::Many(Box::new(Vec::new())))
                .as_vec_mut()
        };
        let idx = vec_ref.len() - 1;
        MutableIterator {
            map: map_ptr,
            key: k,
            values: vec_ref,
            idx,
            last_idx: None,
            collisions: &self.collisions,
            pruned: &self.keys_pruned,
        }
    }

    pub fn update_iter(&mut self, k: &[u8]) -> MutableIterator<'_, T, V> {
        self.make_iter(k)
    }

    pub fn remove_iter(&mut self, k: &[u8]) -> MutableIterator<'_, T, V> {
        self.make_iter(k)
    }

    pub fn remove(&mut self, key: &[u8], prune: impl Fn(&V) -> bool) {
        let k = self.translator.transform(key);
        if let Entry::Occupied(mut occ) = self.map.entry(k) {
            let vec = occ.get_mut().as_vec_mut();
            vec.retain(|v| !prune(v));
            match vec.len() {
                0 => {
                    occ.remove_entry();
                    self.keys_pruned.inc();
                }
                1 => {
                    let v = vec.pop().unwrap();
                    *occ.into_mut() = Record::One(v);
                }
                _ => {}
            }
        }
    }
}
