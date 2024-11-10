use std::cell::RefCell;
use std::rc::Rc;

/// Represents an interval [start, end), where `end` is exclusive.
#[derive(Debug, Clone)]
struct Interval {
    start: u64,
    end: u64,
}

impl Interval {
    fn new(start: u64, end: u64) -> Self {
        Interval { start, end }
    }

    /// Checks if this interval overlaps with another.
    fn overlaps(&self, other: &Interval) -> bool {
        self.start < other.end && other.start < self.end
    }
}

/// A node in the Interval Tree.
#[derive(Debug)]
struct Node {
    interval: Interval,
    max_end: u64,
    left: Option<Rc<RefCell<Node>>>,
    right: Option<Rc<RefCell<Node>>>,
}

impl Node {
    fn new(interval: Interval) -> Self {
        let max_end = interval.end;
        Node {
            interval,
            max_end,
            left: None,
            right: None,
        }
    }
}

#[derive(Debug)]
struct IntervalTree {
    root: Option<Rc<RefCell<Node>>>,
}

impl IntervalTree {
    fn new() -> Self {
        IntervalTree { root: None }
    }

    /// Inserts an interval into the tree, merging overlapping intervals.
    fn insert(&mut self, point: u64) {
        let interval = Interval::new(point, point + 1);
        self.root = Self::insert_node(self.root.take(), interval);
    }

    fn insert_node(
        node: Option<Rc<RefCell<Node>>>,
        interval: Interval,
    ) -> Option<Rc<RefCell<Node>>> {
        match node {
            Some(n) => {
                {
                    // Borrow the node mutably
                    let mut n_borrow = n.borrow_mut();
                    if interval.start < n_borrow.interval.start {
                        n_borrow.left = Self::insert_node(n_borrow.left.take(), interval);
                    } else {
                        n_borrow.right = Self::insert_node(n_borrow.right.take(), interval);
                    }

                    // Update the max_end value
                    n_borrow.max_end = n_borrow
                        .interval
                        .end
                        .max(
                            n_borrow
                                .left
                                .as_ref()
                                .map_or(0, |left| left.borrow().max_end),
                        )
                        .max(
                            n_borrow
                                .right
                                .as_ref()
                                .map_or(0, |right| right.borrow().max_end),
                        );
                }

                // Return node back
                Some(n)
            }
            None => Some(Rc::new(RefCell::new(Node::new(interval)))),
        }
    }

    /// Finds the next gap starting from a given point.
    fn find_next_gap(&self, start: u64) -> Option<Interval> {
        let mut current_point = start;
        loop {
            let overlapping_interval = self.overlapping_interval(current_point);
            match overlapping_interval {
                Some(interval) => {
                    // Move current_point to the end of the overlapping interval
                    current_point = interval.end;
                }
                None => {
                    // No overlapping interval found, find the next occupied interval
                    let next_interval = self.next_interval(current_point);
                    let gap_end = next_interval.map_or(u64::MAX, |iv| iv.start);
                    return Some(Interval::new(current_point, gap_end));
                }
            }
            if current_point == u64::MAX {
                return None;
            }
        }
    }

    /// Finds an interval that overlaps with the given point.
    fn overlapping_interval(&self, point: u64) -> Option<Interval> {
        Self::overlapping_node(&self.root, point)
    }

    fn overlapping_node(node: &Option<Rc<RefCell<Node>>>, point: u64) -> Option<Interval> {
        if let Some(n) = node {
            let n_borrow = n.borrow();
            if n_borrow.interval.start <= point && point < n_borrow.interval.end {
                return Some(n_borrow.interval.clone());
            }

            if let Some(left) = &n_borrow.left {
                if left.borrow().max_end > point {
                    return Self::overlapping_node(&n_borrow.left, point);
                }
            }

            return Self::overlapping_node(&n_borrow.right, point);
        }
        None
    }

    /// Finds the next interval after the given point.
    fn next_interval(&self, point: u64) -> Option<Interval> {
        let mut node = self.root.clone();
        let mut successor: Option<Interval> = None;

        while let Some(n) = node {
            let n_borrow = n.borrow();
            if point < n_borrow.interval.start {
                successor = Some(n_borrow.interval.clone());
                node = n_borrow.left.clone();
            } else {
                node = n_borrow.right.clone();
            }
        }
        successor
    }
}
