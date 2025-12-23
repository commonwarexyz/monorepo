#![no_main]

use arbitrary::Arbitrary;
use commonware_utils::{DurationExt, SystemTimeExt};
use libfuzzer_sys::fuzz_target;
use rand::{rngs::StdRng, SeedableRng};
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
}

fn fuzz(input: FuzzInput) {
    let mut rng = StdRng::seed_from_u64(input.seed);

    match input.operation {
        Operation::ParseDuration { input } => {
            let _ = Duration::parse(&input);
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
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
