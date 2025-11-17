use crate::{
    simplex::{
        signing_scheme::Scheme,
        types::{Nullification, Voter},
    },
    types::View,
    Viewable,
};
use commonware_cryptography::Digest;
use commonware_resolver::Resolver;
use commonware_utils::sequence::U64;
use std::collections::{BTreeMap, BTreeSet};
use tracing::debug;

pub struct State<S: Scheme, D: Digest> {
    nullifications: BTreeMap<View, Nullification<S>>,
    pending: BTreeSet<View>,
    current_view: View,
    floor: Option<Voter<S, D>>,

    fetch_concurrent: usize,
}

impl<S: Scheme, D: Digest> State<S, D> {
    pub fn new(fetch_concurrent: usize) -> Self {
        Self {
            nullifications: BTreeMap::new(),
            pending: BTreeSet::new(),
            current_view: 0,
            floor: None,
            fetch_concurrent,
        }
    }

    pub async fn handle_message(
        &mut self,
        message: Voter<S, D>,
        resolver: &mut impl Resolver<Key = U64>,
    ) {
        match message {
            Voter::Nullification(nullification) => {
                // Update current view
                let view = nullification.view();
                if view > self.current_view {
                    self.current_view = view;
                }

                // If greater than the floor, store
                self.pending.remove(&view);
                resolver.cancel(U64::new(view)).await;
                if let Some(floor) = &self.floor {
                    if view > floor.view() {
                        self.nullifications.insert(view, nullification);
                    }
                } else {
                    self.nullifications.insert(view, nullification);
                }
            }
            Voter::Notarization(notarization) => {
                // Update current view
                let view = notarization.view();
                if view > self.current_view {
                    self.current_view = view;
                }

                // Set last notarized
                if let Some(floor) = &self.floor {
                    if view > floor.view() {
                        self.floor = Some(Voter::Notarization(notarization));
                    }
                } else {
                    self.floor = Some(Voter::Notarization(notarization));
                }

                // Prune old nullifications
                self.prune(resolver).await;
            }
            Voter::Finalization(finalization) => {
                // Update current view
                let view = finalization.view();
                if view > self.current_view {
                    self.current_view = view;
                }

                // Set last finalized
                if let Some(floor) = &self.floor {
                    if view > floor.view() {
                        self.floor = Some(Voter::Finalization(finalization));
                    }
                } else {
                    self.floor = Some(Voter::Finalization(finalization));
                }

                // Prune old nullifications
                self.prune(resolver).await;
            }
            _ => unreachable!("unexpected message type"),
        }

        // Request missing nullifications
        self.request_missing(resolver).await;
    }

    async fn request_missing(&mut self, resolver: &mut impl Resolver<Key = U64>) {
        let mut cursor = self
            .floor
            .as_ref()
            .map(|floor| floor.view().saturating_add(1))
            .unwrap_or(1);

        // We must either receive a nullification or a notarization (at the view or higher),
        // so we don't need to worry about getting stuck because we've only made requests for the
        // next FETCH_BATCH views (which none of which may be resolvable). All will be resolved.
        while cursor < self.current_view && self.pending.len() < self.fetch_concurrent {
            if self.nullifications.contains_key(&cursor) || !self.pending.insert(cursor) {
                cursor = cursor.checked_add(1).expect("view overflow");
                continue;
            }
            self.pending.insert(cursor);
            resolver.fetch(U64::new(cursor)).await;
            debug!(cursor, "requested missing nullification");

            // Increment cursor
            cursor = cursor.checked_add(1).expect("view overflow");
        }
    }

    async fn prune(&mut self, resolver: &mut impl Resolver<Key = U64>) {
        let min = self.floor.as_ref().unwrap().view();
        self.nullifications.retain(|view, _| *view > min);
        self.pending.retain(|view| *view > min);

        let min = U64::from(min);
        resolver.retain(move |key| key > &min).await;
    }

    pub fn produce(&self, view: View) -> Option<Voter<S, D>> {
        // If view is <= floor, return the floor
        if let Some(floor) = &self.floor {
            if view <= floor.view() {
                return Some(floor.clone());
            }
        }

        // Otherwise, return the nullification for the view
        self.nullifications
            .get(&view)
            .map(|nullification| Voter::Nullification(nullification.clone()))
    }
}
