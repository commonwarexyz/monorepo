#![no_main]

use arbitrary::Arbitrary;
use commonware_utils::{DurationExt, FuzzRng, SystemTimeExt};
use libfuzzer_sys::fuzz_target;
use std::time::{Duration, SystemTime};

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    operation: Operation,
    seed: u64,
}

#[derive(Arbitrary, Debug)]
enum Operation {
    ParseDuration {
        input: String,
    },
    SystemTimeEpoch {
        seconds_since_epoch: u64,
    },
    SystemTimeEpochMillis {
        seconds_since_epoch: u64,
    },
    SystemTimeAddJittered {
        seconds_since_epoch: u64,
        jitter_secs: u64,
    },
    FromNanosSaturating {
        nanos: u128,
    },
    SaturatingAddExt {
        seconds_since_epoch: u64,
        delta_secs: u64,
        delta_nanos: u32,
    },
}

fn fuzz(input: FuzzInput) {
    let mut rng = FuzzRng::new(input.seed.to_le_bytes().to_vec());

    match input.operation {
        Operation::ParseDuration { input } => {
            let parsed = Duration::parse(&input);
            // Independent re-derivation of the accepted grammar (suffix precedence
            // ms, h, m, s) cross-checks the parser against an oracle.
            let s = input.trim();
            let oracle = if let Some(n) = s.strip_suffix("ms") {
                n.trim().parse::<u64>().ok().map(Duration::from_millis)
            } else if let Some(n) = s.strip_suffix('h') {
                n.trim()
                    .parse::<u64>()
                    .ok()
                    .and_then(|h| h.checked_mul(3600))
                    .map(Duration::from_secs)
            } else if let Some(n) = s.strip_suffix('m') {
                n.trim()
                    .parse::<u64>()
                    .ok()
                    .and_then(|m| m.checked_mul(60))
                    .map(Duration::from_secs)
            } else if let Some(n) = s.strip_suffix('s') {
                n.trim().parse::<u64>().ok().map(Duration::from_secs)
            } else {
                None
            };
            match (parsed, oracle) {
                (Ok(d), Some(e)) => assert_eq!(d, e),
                (Ok(d), None) => panic!("parser accepted {input:?} as {d:?}; oracle rejected"),
                (Err(_), _) => {}
            }
        }

        Operation::SystemTimeEpoch {
            seconds_since_epoch,
        } => {
            if let Some(duration) =
                Duration::from_secs(seconds_since_epoch).checked_add(Duration::from_secs(0))
            {
                if let Some(time) = SystemTime::UNIX_EPOCH.checked_add(duration) {
                    let epoch = time.epoch();
                    assert_eq!(epoch, duration);
                }
            }
        }

        Operation::SystemTimeEpochMillis {
            seconds_since_epoch,
        } => {
            if let Some(duration) =
                Duration::from_secs(seconds_since_epoch).checked_add(Duration::from_secs(0))
            {
                if let Some(time) = SystemTime::UNIX_EPOCH.checked_add(duration) {
                    let epoch_millis = time.epoch_millis();
                    if let Some(expected_millis) = seconds_since_epoch.checked_mul(1000) {
                        assert_eq!(epoch_millis, expected_millis);
                    } else {
                        assert_eq!(epoch_millis, u64::MAX);
                    }
                }
            }
        }

        Operation::SystemTimeAddJittered {
            seconds_since_epoch,
            jitter_secs,
        } => {
            if let Some(base_duration) =
                Duration::from_secs(seconds_since_epoch).checked_add(Duration::from_secs(0))
            {
                if let Some(base_time) = SystemTime::UNIX_EPOCH.checked_add(base_duration) {
                    let jitter = Duration::from_secs(jitter_secs.min(3600));

                    if let Some(max_jitter) = jitter.checked_mul(2) {
                        if let Some(_max_time) = base_time.checked_add(max_jitter) {
                            let jittered_time = base_time.add_jittered(&mut rng, jitter);

                            assert!(jittered_time >= base_time);
                            assert!(jittered_time <= base_time + (jitter * 2));
                        }
                    }
                }
            }
        }

        Operation::FromNanosSaturating { nanos } => {
            let result = Duration::from_nanos_saturating(nanos);
            if nanos > Duration::MAX.as_nanos() {
                assert_eq!(result, Duration::MAX);
            } else {
                assert_eq!(result.as_nanos(), nanos);
            }
        }

        Operation::SaturatingAddExt {
            seconds_since_epoch,
            delta_secs,
            delta_nanos,
        } => {
            if let Some(base_time) =
                SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(seconds_since_epoch))
            {
                let delta = Duration::new(delta_secs, delta_nanos % 1_000_000_000);
                let result = base_time.saturating_add_ext(delta);
                if delta.is_zero() {
                    assert_eq!(result, base_time);
                } else {
                    assert_eq!(
                        result,
                        base_time.checked_add(delta).unwrap_or(SystemTime::limit())
                    );
                }
            }
        }
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
