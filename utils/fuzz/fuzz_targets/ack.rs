#![no_main]

use arbitrary::Arbitrary;
use commonware_utils::acknowledgement::{Acknowledgement, Exact};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
enum FuzzInput {
    SingleAcknowledge,
    SingleDrop,
    MultipleClones { num_clones: u8 },
    MixedOperations { num_clones: u8, num_acknowledge: u8 },
}

fn fuzz(input: FuzzInput) {
    match input {
        FuzzInput::SingleAcknowledge => {
            let (ack, waiter) = Exact::handle();
            ack.acknowledge();

            futures::executor::block_on(async {
                let _ = waiter.await;
            });
        }

        FuzzInput::SingleDrop => {
            let (ack, waiter) = Exact::handle();
            drop(ack);

            futures::executor::block_on(async {
                let _ = waiter.await;
            });
        }

        FuzzInput::MultipleClones { num_clones } => {
            let (ack, waiter) = Exact::handle();

            let mut clones = vec![ack];
            for _ in 1..num_clones {
                clones.push(clones[0].clone());
            }

            for ack in clones {
                ack.acknowledge();
            }

            futures::executor::block_on(async {
                let _ = waiter.await;
            });
        }

        FuzzInput::MixedOperations {
            num_clones,
            num_acknowledge,
        } => {
            let num_acknowledge = (num_acknowledge as usize).min(num_clones as usize);

            let (ack, waiter) = Exact::handle();

            let mut clones = vec![ack];
            for _ in 1..num_clones {
                clones.push(clones[0].clone());
            }

            for ack in clones.drain(..num_acknowledge) {
                ack.acknowledge();
            }

            drop(clones);

            futures::executor::block_on(async {
                let _ = waiter.await;
            });
        }
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
