use std::cell::RefCell;
use std::rc::Rc;

/// Represents an interval [start, end), where `end` is exclusive.
#[derive(Debug, Clone)]
pub struct Interval {
    start: u64,
    end: u64,
}

impl Interval {
    pub fn new(start: u64, end: u64) -> Self {
        Interval { start, end }
    }

    /// Checks if this interval overlaps with another.
    pub fn overlaps(&self, other: &Interval) -> bool {
        self.start < other.end && other.start < self.end
    }

    fn is_adjacent(&self, other: &Interval) -> bool {
        self.end == other.start || self.start == other.end
    }

    fn overlaps_or_adjacent(&self, other: &Interval) -> bool {
        self.overlaps(other) || self.is_adjacent(other)
    }

    fn merge(&self, other: &Interval) -> Interval {
        Interval {
            start: self.start.min(other.start),
            end: self.end.max(other.end),
        }
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
pub struct IntervalTree {
    root: Option<Rc<RefCell<Node>>>,
}

impl IntervalTree {
    pub fn new() -> Self {
        IntervalTree { root: None }
    }

    /// Inserts an interval into the tree, merging overlapping intervals.
    pub fn insert(&mut self, point: u64) {
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
                    // Extract values needed for updating max_end
                    let left_max_end = n
                        .borrow()
                        .left
                        .as_ref()
                        .map(|left| left.borrow().max_end)
                        .unwrap_or(0);
                    let right_max_end = n
                        .borrow()
                        .right
                        .as_ref()
                        .map(|right| right.borrow().max_end)
                        .unwrap_or(0);

                    // Start mutable borrow
                    let mut n_borrow = n.borrow_mut();

                    if n_borrow.interval.overlaps_or_adjacent(&interval) {
                        // Merge intervals
                        n_borrow.interval = n_borrow.interval.merge(&interval);

                        // Merge with left subtree if necessary
                        if let Some(left_node) = n_borrow.left.take() {
                            let left_interval = left_node.borrow().interval.clone();
                            if n_borrow.interval.overlaps_or_adjacent(&left_interval) {
                                n_borrow.interval = n_borrow.interval.merge(&left_interval);
                                n_borrow.left = left_node.borrow().left.clone();
                                n_borrow.right = Self::merge_subtrees(
                                    n_borrow.right.take(),
                                    left_node.borrow().right.clone(),
                                );
                            } else {
                                n_borrow.left = Some(left_node);
                            }
                        }

                        // Merge with right subtree if necessary
                        if let Some(right_node) = n_borrow.right.take() {
                            let right_interval = right_node.borrow().interval.clone();
                            if n_borrow.interval.overlaps_or_adjacent(&right_interval) {
                                n_borrow.interval = n_borrow.interval.merge(&right_interval);
                                n_borrow.right = right_node.borrow().right.clone();
                                n_borrow.left = Self::merge_subtrees(
                                    n_borrow.left.take(),
                                    right_node.borrow().left.clone(),
                                );
                            } else {
                                n_borrow.right = Some(right_node);
                            }
                        }

                        // Update max_end
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
                    } else if interval.start < n_borrow.interval.start {
                        // Insert into left subtree
                        n_borrow.left = Self::insert_node(n_borrow.left.take(), interval);

                        // Update max_end
                        let left_max_end = n_borrow
                            .left
                            .as_ref()
                            .map(|left| left.borrow().max_end)
                            .unwrap_or(0);
                        n_borrow.max_end =
                            n_borrow.interval.end.max(left_max_end).max(right_max_end);
                    } else {
                        // Insert into right subtree
                        n_borrow.right = Self::insert_node(n_borrow.right.take(), interval);

                        // Update max_end
                        let right_max_end = n_borrow
                            .right
                            .as_ref()
                            .map(|right| right.borrow().max_end)
                            .unwrap_or(0);
                        n_borrow.max_end =
                            n_borrow.interval.end.max(left_max_end).max(right_max_end);
                    }
                }
                Some(n)
            }
            None => Some(Rc::new(RefCell::new(Node::new(interval)))),
        }
    }

    fn merge_subtrees(
        left: Option<Rc<RefCell<Node>>>,
        right: Option<Rc<RefCell<Node>>>,
    ) -> Option<Rc<RefCell<Node>>> {
        match (left, right) {
            (Some(left_node), Some(right_node)) => {
                {
                    // Merge right subtree into left subtree
                    let mut left_borrow = left_node.borrow_mut();
                    left_borrow.right =
                        Self::merge_subtrees(left_borrow.right.take(), Some(right_node));

                    // Update max_end
                    left_borrow.max_end = left_borrow
                        .interval
                        .end
                        .max(left_borrow.left.as_ref().map_or(0, |n| n.borrow().max_end))
                        .max(left_borrow.right.as_ref().map_or(0, |n| n.borrow().max_end));
                }
                Some(left_node)
            }
            (Some(node), None) | (None, Some(node)) => Some(node),
            (None, None) => None,
        }
    }

    /// Finds the next gap starting from a given point.
    pub fn find_next_gap(&self, start: u64) -> Option<Interval> {
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

    fn prune_below(&mut self, value: u64) {
        self.root = Self::prune_below_node(self.root.take(), value);
    }

    fn prune_below_node(node: Option<Rc<RefCell<Node>>>, value: u64) -> Option<Rc<RefCell<Node>>> {
        match node {
            Some(n) => {
                {
                    // Extract values before mutable borrow
                    let left_node = n.borrow().left.clone();

                    // Start mutable borrow
                    let mut n_borrow = n.borrow_mut();

                    // Prune left subtree
                    n_borrow.left = Self::prune_below_node(left_node, value);

                    // Prune current node if it ends before `value`
                    if n_borrow.interval.end <= value {
                        // Replace this node with the right child
                        return Self::prune_below_node(n_borrow.right.take(), value);
                    }

                    // Adjust interval if it overlaps the prune point
                    if n_borrow.interval.start < value {
                        n_borrow.interval.start = value;
                    }

                    // Prune right subtree
                    n_borrow.right = Self::prune_below_node(n_borrow.right.take(), value);

                    // Update max_end
                    let left_max_end = n_borrow
                        .left
                        .as_ref()
                        .map(|left| left.borrow().max_end)
                        .unwrap_or(0);
                    let right_max_end = n_borrow
                        .right
                        .as_ref()
                        .map(|right| right.borrow().max_end)
                        .unwrap_or(0);
                    n_borrow.max_end = n_borrow.interval.end.max(left_max_end).max(right_max_end);
                }

                Some(n)
            }
            None => None,
        }
    }
}
