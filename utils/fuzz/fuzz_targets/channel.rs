#![no_main]

use arbitrary::Arbitrary;
use commonware_utils::channel::tracked;
use futures::executor::block_on;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
enum FuzzInput {
    SendReceive {
        batch: Option<u32>,
        data: Vec<u8>,
    },
    MultipleSends {
        batches: Vec<Option<u32>>,
        data: Vec<Vec<u8>>,
    },
    CloneGuard {
        batch: Option<u32>,
        data: u64,
        num_clones: u8,
    },
    TrySend {
        batch: Option<u32>,
        data: String,
    },
}

fn fuzz(input: FuzzInput) {
    match input {
        FuzzInput::SendReceive { batch, data } => {
            block_on(async {
                let (sender, mut receiver) = tracked::bounded::<Vec<u8>, u32>(10);

                if let Ok(_seq) = sender.send(batch, data.clone()).await {
                    if let Some(b) = batch {
                        let _ = sender.pending(b);
                    }
                    let _ = sender.watermark();

                    if let Some(msg) = receiver.recv().await {
                        let _ = msg.data;
                        drop(msg.guard);
                    }
                }
            });
        }

        FuzzInput::MultipleSends { batches, data } => {
            block_on(async {
                let (sender, mut receiver) = tracked::bounded::<Vec<u8>, u32>(100);

                for (batch, d) in batches.iter().zip(data.iter()) {
                    let _ = sender.send(*batch, d.clone()).await;
                }

                let _ = sender.watermark();

                while let Ok(msg) = receiver.try_recv() {
                    drop(msg);
                }
            });
        }

        FuzzInput::CloneGuard {
            batch,
            data,
            num_clones,
        } => {
            block_on(async {
                let (sender, mut receiver) = tracked::bounded::<u64, u32>(10);

                if let Ok(_seq) = sender.send(batch, data).await {
                    if let Some(msg) = receiver.recv().await {
                        let mut guards = vec![msg.guard];
                        for _ in 0..(num_clones % 10) {
                            guards.push(guards[0].clone());
                        }
                        drop(guards);
                    }

                    let _ = sender.watermark();
                    if let Some(b) = batch {
                        let _ = sender.pending(b);
                    }
                }
            });
        }

        FuzzInput::TrySend { batch, data } => {
            block_on(async {
                let (sender, mut receiver) = tracked::bounded::<String, u32>(5);

                let _ = sender.try_send(batch, data.clone());
                let _ = sender.watermark();

                while let Ok(msg) = receiver.try_recv() {
                    drop(msg);
                }
            });
        }
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
