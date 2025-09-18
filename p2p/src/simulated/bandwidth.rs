use std::{
    collections::BTreeMap,
    time::{Duration, SystemTime},
};

const NS_PER_SEC: u128 = 1_000_000_000;

#[derive(Clone, Debug)]
/// Portion of a transfer executed over a constant-rate window.
pub(super) struct Segment {
    start: SystemTime,
    end: SystemTime,
    bytes: u128,
}

impl Segment {
    fn duration_ns(&self) -> u128 {
        self.end
            .duration_since(self.start)
            .unwrap_or(Duration::ZERO)
            .as_nanos() as u128
    }

    pub(super) fn start_time(&self) -> SystemTime {
        self.start
    }
}

#[derive(Debug)]
/// State for an in-flight transfer managed by the scheduler.
struct Flow {
    bytes_total: u128,
    bytes_delivered: u128,
    ready_time: SystemTime,
    segments: Vec<Segment>,
}

impl Flow {
    fn new(bytes: usize, ready_time: SystemTime) -> Self {
        Self {
            bytes_total: bytes as u128,
            bytes_delivered: 0,
            ready_time,
            segments: Vec::new(),
        }
    }

    fn remaining(&self) -> u128 {
        self.bytes_total.saturating_sub(self.bytes_delivered)
    }

    fn completion_time(&self) -> Option<SystemTime> {
        if let Some(last) = self.segments.last() {
            Some(last.end)
        } else if self.remaining() == 0 {
            Some(self.ready_time)
        } else {
            None
        }
    }
}

pub(super) struct Schedule {
    pub(super) bps: usize,
    flows: BTreeMap<u64, Flow>,
}

impl Schedule {
    pub(super) fn new(bps: usize) -> Self {
        Self {
            bps,
            flows: BTreeMap::new(),
        }
    }

    pub(super) fn add_flow(&mut self, flow_id: u64, start: SystemTime, bytes: usize) {
        let flow = Flow::new(bytes, start);
        let replaced = self.flows.insert(flow_id, flow);
        debug_assert!(replaced.is_none(), "flow id reused");
    }

    /// Discard segments that end before `now`, crediting their bytes to the flow and
    /// trimming partially-completed segments.
    pub(super) fn prune(&mut self, now: SystemTime) {
        let mut completed = Vec::new();
        for (&id, flow) in self.flows.iter_mut() {
            let mut updated = Vec::new();
            for mut segment in flow.segments.drain(..) {
                if segment.end <= now {
                    flow.bytes_delivered = flow.bytes_delivered.saturating_add(segment.bytes);
                } else if segment.start < now {
                    let total_ns = segment.duration_ns().max(1);
                    let elapsed_ns = now
                        .duration_since(segment.start)
                        .unwrap_or(Duration::ZERO)
                        .as_nanos() as u128;
                    let credited = segment.bytes * elapsed_ns / total_ns;
                    let credited = credited.min(segment.bytes);
                    flow.bytes_delivered = flow.bytes_delivered.saturating_add(credited);
                    let remaining_bytes = segment.bytes.saturating_sub(credited);
                    if remaining_bytes > 0 {
                        segment.start = now;
                        segment.bytes = remaining_bytes;
                        updated.push(segment);
                    }
                } else {
                    updated.push(segment);
                }
            }

            flow.segments = updated;
            flow.ready_time = flow.segments.first().map(|s| s.start).unwrap_or(now);

            if flow.remaining() == 0 {
                completed.push(id);
            }
        }

        for id in completed {
            self.flows.remove(&id);
        }
    }

    /// Recompute the GPS schedule for all active flows starting at `start_time`.
    pub(super) fn recompute(&mut self, start_time: SystemTime) {
        if self.bps == usize::MAX {
            self.generate_unlimited_schedule(start_time);
            return;
        }

        let capacity = self.bps as u128;
        if capacity == 0 {
            // No bandwidth: clear segments so completions remain `None`.
            for flow in self.flows.values_mut() {
                flow.segments.clear();
                flow.ready_time = start_time;
            }
            return;
        }

        let mut states: Vec<(u64, SystemTime, u128)> = self
            .flows
            .iter_mut()
            .filter_map(|(&id, flow)| {
                let remaining = flow.remaining();
                flow.segments.clear();
                if remaining == 0 {
                    None
                } else {
                    let ready = if flow.ready_time > start_time {
                        flow.ready_time
                    } else {
                        start_time
                    };
                    Some((id, ready, remaining))
                }
            })
            .collect();

        states.sort_by(|a, b| match a.1.cmp(&b.1) {
            std::cmp::Ordering::Equal => a.0.cmp(&b.0),
            other => other,
        });

        if states.is_empty() {
            return;
        }

        let mut segments: BTreeMap<u64, Vec<Segment>> = BTreeMap::new();
        let mut time = states.iter().map(|(_, t, _)| *t).min().unwrap();

        loop {
            let mut active_indices: Vec<usize> = states
                .iter()
                .enumerate()
                .filter(|(_, (_, ready, remaining))| *remaining > 0 && *ready <= time)
                .map(|(idx, _)| idx)
                .collect();

            if active_indices.is_empty() {
                if let Some(next_ready) = states
                    .iter()
                    .filter(|(_, _, remaining)| *remaining > 0)
                    .map(|(_, ready, _)| *ready)
                    .min()
                {
                    time = next_ready;
                    continue;
                } else {
                    break;
                }
            }

            active_indices.sort_by(|a, b| states[*a].0.cmp(&states[*b].0));
            let active_count = active_indices.len() as u128;

            // Determine the time until the next flow completes.
            let mut delta_ns = u128::MAX;
            let mut finishing = Vec::new();
            for &idx in &active_indices {
                let remaining = states[idx].2;
                let needed = ceil_div_u128(remaining * NS_PER_SEC * active_count, capacity);
                if needed < delta_ns {
                    delta_ns = needed;
                    finishing.clear();
                    finishing.push(idx);
                } else if needed == delta_ns {
                    finishing.push(idx);
                }
            }

            if delta_ns == 0 {
                delta_ns = ceil_div_u128(NS_PER_SEC, capacity);
            }

            let total_bytes_capacity = ceil_div_u128(capacity * delta_ns, NS_PER_SEC);
            if total_bytes_capacity == 0 {
                break;
            }

            let share_floor = total_bytes_capacity / active_count;
            let mut assigned_bytes = Vec::new();
            let mut bytes_assigned_total = 0;

            for &idx in &active_indices {
                let remaining = states[idx].2;
                let mut bytes = share_floor.min(remaining);
                if finishing.contains(&idx) {
                    bytes = remaining;
                }
                assigned_bytes.push((idx, bytes));
                bytes_assigned_total += bytes;
            }

            // Distribute leftover capacity deterministically.
            let mut leftover = total_bytes_capacity.saturating_sub(bytes_assigned_total);
            if leftover > 0 {
                for (idx, bytes) in assigned_bytes.iter_mut() {
                    if leftover == 0 {
                        break;
                    }
                    let remaining = states[*idx].2;
                    if *bytes < remaining {
                        let add = (remaining - *bytes).min(leftover);
                        *bytes += add;
                        leftover -= add;
                    }
                }
            }

            let delta = Duration::from_nanos(delta_ns as u64);
            let end = time + delta;

            for (idx, bytes) in assigned_bytes.into_iter() {
                if bytes == 0 {
                    continue;
                }
                let (flow_id, ready, remaining) = &mut states[idx];
                segments.entry(*flow_id).or_default().push(Segment {
                    start: time,
                    end,
                    bytes,
                });
                *remaining = remaining.saturating_sub(bytes);
                *ready = end;
            }

            time = end;

            if states.iter().all(|(_, _, remaining)| *remaining == 0) {
                break;
            }
        }

        for (&id, flow) in self.flows.iter_mut() {
            if let Some(segs) = segments.remove(&id) {
                flow.ready_time = segs.first().map(|s| s.start).unwrap_or(start_time);
                flow.segments = segs;
            } else {
                flow.ready_time = start_time;
            }
        }
    }

    pub(super) fn completion_time(&self, flow_id: u64) -> Option<SystemTime> {
        self.flows
            .get(&flow_id)
            .and_then(|flow| flow.completion_time())
    }

    pub(super) fn flow_segments(&self, flow_id: u64) -> Option<&[Segment]> {
        self.flows.get(&flow_id).map(|f| f.segments.as_slice())
    }

    fn generate_unlimited_schedule(&mut self, start_time: SystemTime) {
        for flow in self.flows.values_mut() {
            let remaining = flow.remaining();
            if remaining == 0 {
                flow.segments.clear();
                flow.ready_time = start_time;
                continue;
            }
            flow.segments = vec![Segment {
                start: start_time,
                end: start_time,
                bytes: remaining,
            }];
            flow.ready_time = start_time;
        }
    }
}

fn ceil_div_u128(num: u128, denom: u128) -> u128 {
    if denom == 0 {
        return u128::MAX;
    }
    (num + denom - 1) / denom
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn test_fair_share_two_transfers() {
        let now = UNIX_EPOCH;
        let mut schedule = Schedule::new(1000);

        schedule.add_flow(1, now, 2000);
        schedule.recompute(now);

        schedule.prune(now + Duration::from_secs(1));
        schedule.add_flow(2, now + Duration::from_secs(1), 1000);
        schedule.recompute(now + Duration::from_secs(1));

        let seg1 = schedule.flow_segments(1).unwrap();
        let seg2 = schedule.flow_segments(2).unwrap();

        assert_eq!(seg1.len(), 1);
        assert_eq!(seg2.len(), 1);

        // Both flows share the link for two seconds at 500 B/s.
        assert_eq!(seg1[0].start, now + Duration::from_secs(1));
        assert_eq!(seg1[0].end, now + Duration::from_secs(3));
        assert_eq!(seg1[0].bytes, 1000);

        assert_eq!(seg2[0].start, now + Duration::from_secs(1));
        assert_eq!(seg2[0].end, now + Duration::from_secs(3));
        assert_eq!(seg2[0].bytes, 1000);

        let completion = schedule.completion_time(2).unwrap();
        assert_eq!(completion, now + Duration::from_secs(3));
    }

    #[test]
    fn test_fair_share_three_transfers() {
        let now = UNIX_EPOCH;
        let mut schedule = Schedule::new(1200);

        schedule.add_flow(1, now, 1200);
        schedule.recompute(now);

        let advance = Duration::from_millis(200);
        schedule.prune(now + advance);

        schedule.add_flow(2, now + advance, 600);
        schedule.add_flow(3, now + advance, 600);
        schedule.recompute(now + advance);

        let seg1 = schedule.flow_segments(1).unwrap();
        let seg2 = schedule.flow_segments(2).unwrap();
        let seg3 = schedule.flow_segments(3).unwrap();

        assert_eq!(seg1.len(), 2);
        assert_eq!(seg2.len(), 1);
        assert_eq!(seg3.len(), 1);

        assert_eq!(seg1[0].start, now + advance);
        assert_eq!(seg1[0].end, now + advance + Duration::from_millis(1500));
        assert_eq!(seg1[0].bytes, 600);

        assert_eq!(seg1[1].start, seg1[0].end);
        assert_eq!(seg1[1].end, now + Duration::from_secs(2));
        assert_eq!(seg1[1].bytes, 360);

        assert_eq!(seg2[0].start, now + advance);
        assert_eq!(seg2[0].end, now + advance + Duration::from_millis(1500));
        assert_eq!(seg2[0].bytes, 600);

        assert_eq!(seg3[0].start, seg2[0].start);
        assert_eq!(seg3[0].end, seg2[0].end);
        assert_eq!(seg3[0].bytes, 600);

        assert_eq!(
            schedule.completion_time(2).unwrap(),
            now + advance + Duration::from_millis(1500)
        );
        assert_eq!(
            schedule.completion_time(3).unwrap(),
            now + advance + Duration::from_millis(1500)
        );
        assert_eq!(
            schedule.completion_time(1).unwrap(),
            now + Duration::from_secs(2)
        );
    }

    #[test]
    fn test_unlimited_capacity() {
        let now = UNIX_EPOCH;
        let mut schedule = Schedule::new(usize::MAX);
        schedule.add_flow(1, now, 1024);
        schedule.recompute(now);
        let segments = schedule.flow_segments(1).unwrap();
        assert_eq!(segments.len(), 1);
        assert_eq!(segments[0].start, now);
        assert_eq!(segments[0].end, now);
        assert_eq!(segments[0].bytes, 1024);
    }

    #[test]
    fn test_capacity_respected() {
        let now = UNIX_EPOCH;
        let mut schedule = Schedule::new(1500);

        schedule.add_flow(1, now, 1500);
        schedule.add_flow(2, now, 1500);
        schedule.add_flow(3, now, 1500);
        schedule.recompute(now);

        let mut boundaries = Vec::new();
        for flow in [1u64, 2, 3] {
            if let Some(segs) = schedule.flow_segments(flow) {
                for segment in segs {
                    boundaries.push(segment.start);
                    boundaries.push(segment.end);
                }
            }
        }

        boundaries.sort();
        boundaries.dedup();

        for pair in boundaries.windows(2) {
            let interval_start = pair[0];
            let interval_end = pair[1];
            if interval_end <= interval_start {
                continue;
            }

            let interval_ns = interval_end
                .duration_since(interval_start)
                .unwrap()
                .as_nanos() as u128;

            let mut bytes_in_interval = 0u128;

            for flow in [1u64, 2, 3] {
                if let Some(segs) = schedule.flow_segments(flow) {
                    for segment in segs {
                        if segment.end <= interval_start || segment.start >= interval_end {
                            continue;
                        }
                        let seg_start = segment.start.max(interval_start);
                        let seg_end = segment.end.min(interval_end);
                        let overlap_ns =
                            seg_end.duration_since(seg_start).unwrap().as_nanos() as u128;
                        let total_ns = segment.duration_ns().max(1);
                        let contributed = segment.bytes * overlap_ns / total_ns;
                        bytes_in_interval += contributed;
                    }
                }
            }

            let rate = bytes_in_interval * NS_PER_SEC / interval_ns;
            assert!(rate <= 1500, "rate {} exceeds capacity", rate);
        }
    }

    #[test]
    fn test_prune_drops_completed_flows() {
        let now = UNIX_EPOCH;
        let mut schedule = Schedule::new(1000);

        schedule.add_flow(1, now, 1000);
        schedule.recompute(now);

        // Entire flow should complete within 1 second at 1000 B/s.
        let completion = schedule.completion_time(1).unwrap();
        assert_eq!(completion, now + Duration::from_secs(1));

        // Prune after completion and ensure flow is removed.
        schedule.prune(now + Duration::from_secs(2));
        assert!(schedule.flow_segments(1).is_none());
    }
}
