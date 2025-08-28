use std::{
    collections::{btree_map, BTreeMap},
    iter::Peekable,
    time::{Duration, SystemTime},
};

/// Encapsulates bandwidth scheduling for a single direction (egress or ingress).
///
/// This struct manages bandwidth allocations over time using a delta-based approach.
/// Each entry in the schedule represents a change in bandwidth usage at a specific time.
pub(super) struct BandwidthSchedule {
    /// Map of time -> bandwidth delta. Positive deltas increase usage, negative decrease.
    pub(super) schedule: BTreeMap<SystemTime, isize>,
    /// Maximum bandwidth capacity in bytes per second. usize::MAX represents unlimited.
    pub(super) bandwidth_bps: usize,
}

impl BandwidthSchedule {
    /// Creates a new bandwidth schedule with the specified capacity.
    pub(super) fn new(bandwidth_bps: usize) -> Self {
        Self {
            schedule: BTreeMap::new(),
            bandwidth_bps,
        }
    }

    /// Prunes events before the specified time and returns current bandwidth usage.
    ///
    /// Events in the past are removed and their deltas summed to calculate
    /// the bandwidth currently in use.
    pub(super) fn prune_and_get_usage(&mut self, now: SystemTime) -> isize {
        let future = self.schedule.split_off(&now);
        let used = self.schedule.values().sum::<isize>().max(0);
        self.schedule = future;
        used
    }

    /// Calculates available bandwidth given the current usage.
    ///
    /// Returns the amount of bandwidth that can be used for new transfers,
    /// accounting for the bandwidth already in use.
    pub(super) fn available_bandwidth(&self, used: isize) -> usize {
        if self.bandwidth_bps == usize::MAX {
            usize::MAX
        } else {
            (self.bandwidth_bps as isize - used).max(0) as usize
        }
    }

    /// Adds a bandwidth reservation from start to end time.
    ///
    /// The bandwidth is allocated at start and released at end.
    pub(super) fn add_reservation(&mut self, start: SystemTime, end: SystemTime, bandwidth: isize) {
        self.insert_point(start, bandwidth);
        self.insert_point(end, -bandwidth);
    }

    /// Inserts a bandwidth delta at the specified time.
    ///
    /// Zero deltas are automatically removed to keep the schedule compact.
    fn insert_point(&mut self, time: SystemTime, delta: isize) {
        if delta == 0 {
            return;
        }
        let entry = self.schedule.entry(time).or_default();
        *entry += delta;
        if *entry == 0 {
            self.schedule.remove(&time);
        }
    }
}

/// Represents a bandwidth reservation for a transfer.
///
/// A reservation allocates bandwidth from `start` to `end` time.
pub(super) struct Reservation {
    /// When the transfer begins.
    pub(super) start: SystemTime,
    /// When the transfer completes.
    pub(super) end: SystemTime,
    /// Bandwidth allocated in bytes per second.
    pub(super) bandwidth: isize,
}

/// Iterator that merges two bandwidth schedules chronologically.
///
/// This iterator processes events from both sender and receiver schedules
/// in time order, aggregating all bandwidth changes at each timestamp.
struct MergedScheduleIterator<'a> {
    sender: Peekable<btree_map::Iter<'a, SystemTime, isize>>,
    receiver: Peekable<btree_map::Iter<'a, SystemTime, isize>>,
}

impl<'a> MergedScheduleIterator<'a> {
    /// Creates a new iterator over the sender and receiver schedules.
    fn new(
        sender: &'a BTreeMap<SystemTime, isize>,
        receiver: &'a BTreeMap<SystemTime, isize>,
    ) -> Self {
        Self {
            sender: sender.iter().peekable(),
            receiver: receiver.iter().peekable(),
        }
    }

    /// Returns the next event time without consuming any items.
    fn peek_time(&mut self) -> Option<SystemTime> {
        let sender_time = self.sender.peek().map(|(&t, _)| t);
        let receiver_time = self.receiver.peek().map(|(&t, _)| t);

        match (sender_time, receiver_time) {
            (Some(s), Some(r)) => Some(s.min(r)),
            (Some(s), None) => Some(s),
            (None, Some(r)) => Some(r),
            (None, None) => None,
        }
    }

    /// Consumes all bandwidth deltas at the specified time from an iterator.
    ///
    /// Returns the sum of all deltas at exactly this timestamp.
    fn consume_deltas(
        iter: &mut Peekable<btree_map::Iter<'a, SystemTime, isize>>,
        time: SystemTime,
    ) -> isize {
        let mut delta = 0;
        while let Some((&t, &d)) = iter.peek() {
            if t == time {
                delta += d;
                iter.next();
            } else {
                break;
            }
        }
        delta
    }
}

impl<'a> Iterator for MergedScheduleIterator<'a> {
    type Item = (SystemTime, isize, isize); // (event_time, sender_delta, receiver_delta)

    fn next(&mut self) -> Option<Self::Item> {
        let next_time = self.peek_time()?;

        let sender_delta = Self::consume_deltas(&mut self.sender, next_time);
        let receiver_delta = Self::consume_deltas(&mut self.receiver, next_time);

        Some((next_time, sender_delta, receiver_delta))
    }
}

/// Calculates the amount of data that can be transferred in a given time window.
///
/// # Parameters
/// - `remaining_data`: Bytes still to transfer
/// - `bandwidth_bps`: Available bandwidth in bytes per second
/// - `window_duration`: Time until next bandwidth change (`None` if no future events)
///
/// Returns a tuple `(bytes_transferred, time_taken)`.
fn calculate_window_transfer(
    remaining_data: f64,
    bandwidth_bps: usize,
    window_duration: Option<Duration>,
) -> (f64, Duration) {
    if bandwidth_bps == usize::MAX {
        // Unlimited bandwidth: transfer is instantaneous
        return (remaining_data, Duration::ZERO);
    }

    if bandwidth_bps == 0 {
        // No bandwidth: no transfer can occur
        return (0.0, window_duration.unwrap_or(Duration::ZERO));
    }

    let time_needed = Duration::from_secs_f64(remaining_data / bandwidth_bps as f64);

    match window_duration {
        Some(duration) => {
            if time_needed <= duration {
                // Entire transfer fits within the window
                (remaining_data, time_needed)
            } else {
                // Window will be completely filled
                let amount = bandwidth_bps as f64 * duration.as_secs_f64();
                (amount, duration)
            }
        }
        None => {
            // No upcoming events, transfer takes exactly the time needed
            (remaining_data, time_needed)
        }
    }
}

/// Calculates bandwidth reservations needed for a transfer, returning the
/// reservations that would be needed.
///
/// # Parameters
/// - `data_size`: Total bytes to transfer
/// - `now`: Current time
/// - `sender`: Sender's bandwidth schedule and current bandwidth usage
/// - `receiver`: Optional receiver schedule and usage (`None` if not delivering)
///
/// Returns a tuple `(reservations, completion_time)`.
pub(super) fn calculate_reservations(
    data_size: usize,
    now: SystemTime,
    sender: (&BandwidthSchedule, isize),
    receiver: Option<(&BandwidthSchedule, isize)>,
) -> (Vec<Reservation>, SystemTime) {
    if data_size == 0 {
        return (Vec::new(), now);
    }

    let mut reservations = Vec::new();
    let mut current_time = now;
    let mut remaining_data = data_size as f64;
    let mut sender_used_bandwidth = sender.1;
    let mut receiver_used_bandwidth = receiver.as_ref().map(|(_, usage)| *usage).unwrap_or(0);

    // Create merged iterator for both schedules
    let empty_schedule = BTreeMap::new();

    let mut events = if let Some((receiver, _)) = receiver.as_ref() {
        MergedScheduleIterator::new(&sender.0.schedule, &receiver.schedule)
    } else {
        MergedScheduleIterator::new(&sender.0.schedule, &empty_schedule)
    };

    loop {
        // Calculate current available bandwidth
        let sender_available = sender.0.available_bandwidth(sender_used_bandwidth);
        let receiver_available = receiver
            .as_ref()
            .map(|(r, _)| r.available_bandwidth(receiver_used_bandwidth))
            .unwrap_or(usize::MAX);

        let bandwidth = sender_available.min(receiver_available);

        // Determine the duration of this window
        let window = events
            .peek_time()
            .and_then(|t| t.duration_since(current_time).ok());

        // Calculate transfer and create reservation if progress can be made
        let (amount, duration) = calculate_window_transfer(remaining_data, bandwidth, window);

        if amount > 0.0 {
            let end_time = current_time + duration;

            reservations.push(Reservation {
                start: current_time,
                end: end_time,
                bandwidth: bandwidth as isize,
            });

            remaining_data -= amount;
        }

        // Check for completion
        if remaining_data <= 0.0 {
            break;
        }

        // Advance to the next state
        if let Some((event_time, sender_delta, receiver_delta)) = events.next() {
            // Move time forward to the next event
            current_time = event_time;
            sender_used_bandwidth += sender_delta;
            receiver_used_bandwidth += receiver_delta;
        } else {
            // No more events. If we are here, it means remaining > 0 but
            // we cannot make any more progress (e.g. bandwidth is 0)
            break;
        }
    }

    let completion = reservations.last().map(|r| r.end).unwrap_or(now);
    (reservations, completion)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn test_calculate_window_transfer() {
        // Unlimited bandwidth
        let (amount, duration) =
            calculate_window_transfer(1000.0, usize::MAX, Some(Duration::from_secs(10)));
        assert_eq!(amount, 1000.0);
        assert_eq!(duration, Duration::ZERO);

        // Zero bandwidth
        let window = Duration::from_secs(5);
        let (amount, duration) = calculate_window_transfer(1000.0, 0, Some(window));
        assert_eq!(amount, 0.0);
        assert_eq!(duration, window);

        // Transfer fits within the window
        let (amount, duration) = calculate_window_transfer(
            1000.0,
            1000,                         // 1000 B/s
            Some(Duration::from_secs(2)), // 2 second window
        );
        assert_eq!(amount, 1000.0);
        assert_eq!(duration, Duration::from_secs(1)); // 1000 bytes at 1000 B/s = 1s

        // Transfer fills the window completely
        let (amount, duration) = calculate_window_transfer(
            2000.0,
            1000,                         // 1000 B/s
            Some(Duration::from_secs(1)), // 1 second window
        );
        assert_eq!(amount, 1000.0); // Can only transfer 1000 bytes in 1s at 1000 B/s
        assert_eq!(duration, Duration::from_secs(1));

        // No window limit (open-ended transfer)
        let (amount, duration) = calculate_window_transfer(
            5000.0, 1000, // 1000 B/s
            None,
        );
        assert_eq!(amount, 5000.0);
        assert_eq!(duration, Duration::from_secs(5)); // 5000 bytes at 1000 B/s = 5s
    }

    #[test]
    fn test_calculate_reservations_simple() {
        let now = UNIX_EPOCH;

        // Unlimited bandwidth on both ends
        let sender_schedule = BandwidthSchedule::new(usize::MAX);
        let (reservations, completion) = calculate_reservations(
            1000,
            now,
            (&sender_schedule, 0),
            None, // No receiver constraint
        );
        assert_eq!(reservations.len(), 1);
        assert_eq!(reservations[0].bandwidth, usize::MAX as isize);
        assert_eq!(reservations[0].start, now);
        assert_eq!(reservations[0].end, now); // Instant transfer
        assert_eq!(completion, now);

        // Limited by sender bandwidth (1000 B/s, 1000 bytes = 1s)
        let sender_schedule = BandwidthSchedule::new(1000);
        let (reservations, completion) =
            calculate_reservations(1000, now, (&sender_schedule, 0), None);
        assert_eq!(reservations.len(), 1);
        assert_eq!(reservations[0].bandwidth, 1000);
        assert_eq!(reservations[0].start, now);
        assert_eq!(reservations[0].end, now + Duration::from_secs(1));
        assert_eq!(completion, now + Duration::from_secs(1));

        // Limited by receiver bandwidth
        let sender_schedule = BandwidthSchedule::new(usize::MAX);
        let receiver_schedule = BandwidthSchedule::new(500); // 500 B/s
        let (reservations, completion) = calculate_reservations(
            1000,
            now,
            (&sender_schedule, 0),
            Some((&receiver_schedule, 0)),
        );
        assert_eq!(reservations.len(), 1);
        assert_eq!(reservations[0].bandwidth, 500);
        assert_eq!(reservations[0].start, now);
        assert_eq!(reservations[0].end, now + Duration::from_secs(2)); // 1000 bytes at 500 B/s = 2s
        assert_eq!(completion, now + Duration::from_secs(2));

        // Limited by minimum of sender and receiver bandwidth
        let sender_schedule = BandwidthSchedule::new(2000);
        let receiver_schedule = BandwidthSchedule::new(1000); // Receiver is bottleneck
        let (reservations, completion) = calculate_reservations(
            3000,
            now,
            (&sender_schedule, 0),
            Some((&receiver_schedule, 0)),
        );
        assert_eq!(reservations.len(), 1);
        assert_eq!(reservations[0].bandwidth, 1000); // Min of 2000 and 1000
        assert_eq!(reservations[0].start, now);
        assert_eq!(reservations[0].end, now + Duration::from_secs(3)); // 3000 bytes at 1000 B/s = 3s
        assert_eq!(completion, now + Duration::from_secs(3));
    }

    #[test]
    fn test_calculate_reservations_with_existing_traffic() {
        let now = UNIX_EPOCH;

        // Partial capacity available
        // Create a sender schedule with existing traffic: 500 B/s used from t=1s to t=2s
        let mut sender_schedule = BandwidthSchedule::new(1000); // 1000 B/s total capacity
        sender_schedule
            .schedule
            .insert(now + Duration::from_secs(1), 500); // Start using 500 B/s at t=1s
        sender_schedule
            .schedule
            .insert(now + Duration::from_secs(2), -500); // Stop at t=2s

        // Send 2000 bytes starting at t=0
        let (reservations, completion) = calculate_reservations(
            2000,
            now,
            (&sender_schedule, 0), // No current usage at t=0
            None,
        );

        // Should create 3 reservations:
        // 1. t=0 to t=1s at 1000 B/s (1000 bytes)
        // 2. t=1s to t=2s at 500 B/s (500 bytes)
        // 3. t=2s onward at 1000 B/s (remaining 500 bytes, 0.5s)
        assert_eq!(reservations.len(), 3);
        assert_eq!(reservations[0].bandwidth, 1000);
        assert_eq!(reservations[0].start, now);
        assert_eq!(reservations[0].end, now + Duration::from_secs(1));

        assert_eq!(reservations[1].bandwidth, 500);
        assert_eq!(reservations[1].start, now + Duration::from_secs(1));
        assert_eq!(reservations[1].end, now + Duration::from_secs(2));

        assert_eq!(reservations[2].bandwidth, 1000);
        assert_eq!(reservations[2].start, now + Duration::from_secs(2));
        assert_eq!(reservations[2].end, now + Duration::from_millis(2500));

        assert_eq!(completion, now + Duration::from_millis(2500));

        // No capacity available initially (should return empty)
        let mut full_schedule = BandwidthSchedule::new(1000);
        full_schedule.schedule.insert(now, 1000); // Use full capacity from t=0
        full_schedule
            .schedule
            .insert(now + Duration::from_secs(2), -1000); // Free at t=2s

        let (reservations, completion) = calculate_reservations(
            1000,
            now,
            (&full_schedule, 1000), // Full capacity used at t=0
            None,
        );

        // No bandwidth available, so no reservations can be made
        // No reservations means completion time is now
        assert_eq!(reservations.len(), 0);
        assert_eq!(completion, now);
    }

    #[test]
    fn test_calculate_reservations_staggered() {
        let now = UNIX_EPOCH;

        // Create a simple staggered scenario with bandwidth that becomes available
        let sender_schedule = BandwidthSchedule::new(1000); // 1000 B/s total

        // No existing traffic, just test a simple transfer
        let (reservations, completion) = calculate_reservations(
            1500, // 1500 bytes
            now,
            (&sender_schedule, 0), // No current usage
            None,
        );

        // Should create a single reservation at 1000 B/s for 1.5 seconds
        assert_eq!(reservations.len(), 1);
        assert_eq!(reservations[0].bandwidth, 1000);
        assert_eq!(reservations[0].start, now);
        assert_eq!(reservations[0].end, now + Duration::from_millis(1500));
        assert_eq!(completion, now + Duration::from_millis(1500));
    }

    #[test]
    fn test_bandwidth_schedule_operations() {
        let mut schedule = BandwidthSchedule::new(1000);
        let now = UNIX_EPOCH;

        // Test prune_and_get_usage with no past events
        let usage = schedule.prune_and_get_usage(now);
        assert_eq!(usage, 0);

        // Add some events
        schedule.schedule.insert(now - Duration::from_secs(2), 500); // Past event
        schedule.schedule.insert(now - Duration::from_secs(1), -200); // Past event
        schedule.schedule.insert(now + Duration::from_secs(1), 300); // Future event

        // Prune and check usage (500 - 200 = 300)
        let usage = schedule.prune_and_get_usage(now);
        assert_eq!(usage, 300);
        assert_eq!(schedule.schedule.len(), 1); // Only future event remains
        assert!(schedule
            .schedule
            .contains_key(&(now + Duration::from_secs(1))));

        // Test available_bandwidth
        assert_eq!(schedule.available_bandwidth(0), 1000);
        assert_eq!(schedule.available_bandwidth(300), 700);
        assert_eq!(schedule.available_bandwidth(1000), 0);
        assert_eq!(schedule.available_bandwidth(1500), 0); // Over capacity

        // Test add_reservation
        let start = now + Duration::from_secs(2);
        let end = now + Duration::from_secs(3);
        schedule.add_reservation(start, end, 400);
        assert_eq!(schedule.schedule[&start], 400);
        assert_eq!(schedule.schedule[&end], -400);

        // Test zero removal in insert_point
        schedule.insert_point(end, 400); // This should cancel out the -400
        assert!(!schedule.schedule.contains_key(&end));
    }

    #[test]
    fn test_merged_schedule_iterator() {
        let now = UNIX_EPOCH;

        let mut sender_schedule = BTreeMap::new();
        sender_schedule.insert(now + Duration::from_secs(1), 100);
        sender_schedule.insert(now + Duration::from_secs(3), -100);
        sender_schedule.insert(now + Duration::from_secs(5), 200);

        let mut receiver_schedule = BTreeMap::new();
        receiver_schedule.insert(now + Duration::from_secs(2), 50);
        receiver_schedule.insert(now + Duration::from_secs(3), -50);
        receiver_schedule.insert(now + Duration::from_secs(4), 150);

        let mut iter = MergedScheduleIterator::new(&sender_schedule, &receiver_schedule);

        // Should get events in chronological order
        let (t1, s1, r1) = iter.next().unwrap();
        assert_eq!(t1, now + Duration::from_secs(1));
        assert_eq!(s1, 100);
        assert_eq!(r1, 0);

        let (t2, s2, r2) = iter.next().unwrap();
        assert_eq!(t2, now + Duration::from_secs(2));
        assert_eq!(s2, 0);
        assert_eq!(r2, 50);

        let (t3, s3, r3) = iter.next().unwrap();
        assert_eq!(t3, now + Duration::from_secs(3));
        assert_eq!(s3, -100); // Both have events at t=3
        assert_eq!(r3, -50);

        let (t4, s4, r4) = iter.next().unwrap();
        assert_eq!(t4, now + Duration::from_secs(4));
        assert_eq!(s4, 0);
        assert_eq!(r4, 150);

        let (t5, s5, r5) = iter.next().unwrap();
        assert_eq!(t5, now + Duration::from_secs(5));
        assert_eq!(s5, 200);
        assert_eq!(r5, 0);

        assert!(iter.next().is_none());
    }
}
