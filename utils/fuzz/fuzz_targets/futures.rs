#![no_main]

use arbitrary::Arbitrary;
use commonware_utils::futures::Pool;
use futures::executor::block_on;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    operations: Vec<Operation>,
}

#[derive(Arbitrary, Debug)]
enum Operation {
    Push { value: i32 },
    NextCompleted { limit: u8 },
    CancelAll,
    CheckLen,
    CheckIsEmpty,
}

fn fuzz(input: FuzzInput) {
    block_on(async {
        let mut pool = Pool::<i32>::default();
        let mut expected_count = 0;
        let mut completed_count = 0;

        for op in input.operations {
            match op {
                Operation::Push { value } => {
                    pool.push(async move { value });
                    expected_count += 1;
                    assert_eq!(pool.len(), expected_count - completed_count);
                }

                Operation::NextCompleted { limit } => {
                    let max_iterations = limit.min(10) as usize;
                    for _ in 0..max_iterations {
                        if expected_count > completed_count {
                            pool.next_completed().await;
                            completed_count += 1;
                        } else {
                            break;
                        }
                    }
                }

                Operation::CancelAll => {
                    pool.cancel_all();
                    expected_count = 0;
                    completed_count = 0;
                    assert_eq!(pool.len(), 0);
                    assert!(pool.is_empty());
                }

                Operation::CheckLen => {
                    assert_eq!(pool.len(), expected_count - completed_count);
                }

                Operation::CheckIsEmpty => {
                    assert_eq!(pool.is_empty(), expected_count == completed_count);
                }
            }
        }

        while expected_count > completed_count {
            pool.next_completed().await;
            completed_count += 1;
        }

        assert_eq!(pool.len(), 0);
        assert!(pool.is_empty());
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
