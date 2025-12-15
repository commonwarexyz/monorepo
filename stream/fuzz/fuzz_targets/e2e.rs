#![no_main]

use commonware_cryptography::{ed25519::PrivateKey, Signer};
use commonware_runtime::{deterministic, mocks, Handle, Runner as _, Spawner};
use commonware_stream::{
    dial, listen,
    utils::codec::{recv_frame, send_frame},
    Config, Error, Receiver, Sender,
};
use futures::future::{select, Either};
use libfuzzer_sys::fuzz_target;
use std::time::Duration;

const NAMESPACE: &[u8] = b"fuzz_transport";
const MAX_MESSAGE_SIZE: usize = 2048;

#[derive(Debug)]
enum Direction {
    D2L,
    L2D,
}

impl<'a> arbitrary::Arbitrary<'a> for Direction {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let out = if bool::arbitrary(u)? {
            Self::D2L
        } else {
            Self::L2D
        };
        Ok(out)
    }
}

#[derive(Debug)]
enum Message {
    Authenticated(Direction, Vec<u8>),
    Unauthenticated(Direction, Vec<u8>),
}

impl<'a> arbitrary::Arbitrary<'a> for Message {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let direction = Direction::arbitrary(u)?;
        let msg = Vec::arbitrary(u)?;
        let out = if bool::arbitrary(u)? {
            Self::Authenticated(direction, msg)
        } else {
            Self::Unauthenticated(direction, msg)
        };
        Ok(out)
    }
}

#[derive(Debug)]
pub struct FuzzInput {
    setup_corruption: Vec<u8>,
    messages: Vec<Message>,
}

impl FuzzInput {
    fn has_setup_corruption(&self) -> bool {
        self.setup_corruption.iter().any(|&x| x != 0)
    }
}

impl<'a> arbitrary::Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let setup_corruption = if bool::arbitrary(u)? {
            Vec::arbitrary(u)?
        } else {
            Vec::new()
        };
        let messages = u.arbitrary_iter()?.collect::<Result<Vec<Message>, _>>()?;
        Ok(Self {
            setup_corruption,
            messages,
        })
    }
}

fn fuzz(input: FuzzInput) {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let has_setup_corruption = input.has_setup_corruption();
        let FuzzInput {
            setup_corruption,
            messages,
        } = input;
        let dialer_crypto = PrivateKey::from_seed(42);
        let listener_crypto = PrivateKey::from_seed(24);

        let (dialer_sink, mut adversary_d_stream) = mocks::Channel::init();
        let (mut adversary_d_sink, listener_stream) = mocks::Channel::init();
        let (listener_sink, mut adversary_l_stream) = mocks::Channel::init();
        let (mut adversary_l_sink, dialer_stream) = mocks::Channel::init();

        let dialer_config = Config {
            signing_key: dialer_crypto.clone(),
            namespace: NAMESPACE.to_vec(),
            max_message_size: MAX_MESSAGE_SIZE,
            synchrony_bound: Duration::from_secs(1),
            max_handshake_age: Duration::from_secs(1),
            handshake_timeout: Duration::from_secs(1),
        };

        let listener_config = Config {
            signing_key: listener_crypto.clone(),
            namespace: NAMESPACE.to_vec(),
            max_message_size: MAX_MESSAGE_SIZE,
            synchrony_bound: Duration::from_secs(1),
            max_handshake_age: Duration::from_secs(1),
            handshake_timeout: Duration::from_secs(1),
        };

        let dialer_handle = context.clone().spawn(move |context| async move {
            dial(
                context,
                dialer_config,
                listener_crypto.public_key(),
                dialer_stream,
                dialer_sink,
            )
            .await
        });
        let listener_handle = context.clone().spawn(move |context| async move {
            listen(
                context,
                |_| async { true },
                listener_config,
                listener_stream,
                listener_sink,
            )
            .await
        });
        let adversary_handle: Handle<Result<_, Error>> =
            context.clone().spawn(move |_context| async move {
                let mut corruption_i = 0;

                let announce = recv_frame(&mut adversary_d_stream, MAX_MESSAGE_SIZE).await?;
                send_frame(&mut adversary_d_sink, &announce, MAX_MESSAGE_SIZE).await?;

                let mut m1 = recv_frame(&mut adversary_d_stream, MAX_MESSAGE_SIZE)
                    .await?
                    .to_vec();
                for byte in m1.iter_mut() {
                    if corruption_i < setup_corruption.len() {
                        *byte ^= setup_corruption[corruption_i];
                        corruption_i += 1;
                    }
                }
                send_frame(&mut adversary_d_sink, &m1, MAX_MESSAGE_SIZE).await?;

                let mut m2 = recv_frame(&mut adversary_l_stream, MAX_MESSAGE_SIZE)
                    .await?
                    .to_vec();
                for byte in m2.iter_mut() {
                    if corruption_i < setup_corruption.len() {
                        *byte ^= setup_corruption[corruption_i];
                        corruption_i += 1;
                    }
                }
                send_frame(&mut adversary_l_sink, &m2, MAX_MESSAGE_SIZE).await?;

                let mut m3 = recv_frame(&mut adversary_d_stream, MAX_MESSAGE_SIZE)
                    .await?
                    .to_vec();
                for byte in m3.iter_mut() {
                    if corruption_i < setup_corruption.len() {
                        *byte ^= setup_corruption[corruption_i];
                        corruption_i += 1;
                    }
                }
                let sent_corrupted_data =
                    setup_corruption.iter().take(corruption_i).any(|x| *x != 0);
                send_frame(&mut adversary_d_sink, &m3, MAX_MESSAGE_SIZE).await?;
                Ok((
                    sent_corrupted_data,
                    adversary_d_stream,
                    adversary_d_sink,
                    adversary_l_stream,
                    adversary_l_sink,
                ))
            });
        // We need to do a selection to correctly assert the errors, avoiding deadlock.
        //
        // A deadlock might happen if one side asserts an error, and then we're foolishly waiting
        // for it to send a message it never will.
        let (d_res, l_res) = match select(dialer_handle, listener_handle).await {
            Either::Left((d_res, l_handle)) => {
                match d_res.inspect_err(|e| println!("A: {e:?}")).unwrap().ok() {
                    Some(d_res) => (Some(d_res), l_handle.await.unwrap().ok()),
                    None => (None, None),
                }
            }
            Either::Right((l_res, d_handle)) => {
                match l_res.inspect_err(|e| println!("B: {e:?}")).unwrap().ok() {
                    Some(l_res) => (d_handle.await.unwrap().ok(), Some(l_res)),
                    None => (None, None),
                }
            }
        };
        if d_res.is_none() || l_res.is_none() {
            assert!(has_setup_corruption, "expected there to be data corruption");
            return;
        }
        let (mut d_sender, mut d_receiver) = d_res.unwrap();
        let (_, mut l_sender, mut l_receiver) = l_res.unwrap();
        let (
            sent_corrupted_data,
            mut adversary_d_stream,
            mut adversary_d_sink,
            mut adversary_l_stream,
            mut adversary_l_sink,
        ) = adversary_handle.await.unwrap().unwrap();
        // Importantly, make sure that if we've gotten to this point, no data corruption
        // has happened!
        assert!(!sent_corrupted_data);
        for msg in messages {
            match msg {
                Message::Authenticated(direction, data) => {
                    let (sender, a_in, a_out, receiver): (
                        &mut Sender<mocks::Sink>,
                        &mut mocks::Stream,
                        &mut mocks::Sink,
                        &mut Receiver<mocks::Stream>,
                    ) = match direction {
                        Direction::D2L => (
                            &mut d_sender,
                            &mut adversary_d_stream,
                            &mut adversary_d_sink,
                            &mut l_receiver,
                        ),
                        Direction::L2D => (
                            &mut l_sender,
                            &mut adversary_l_stream,
                            &mut adversary_l_sink,
                            &mut d_receiver,
                        ),
                    };
                    sender.send(&data).await.unwrap();
                    let frame = recv_frame(a_in, MAX_MESSAGE_SIZE).await.unwrap();
                    send_frame(a_out, &frame, MAX_MESSAGE_SIZE).await.unwrap();
                    let data2 = receiver.recv().await.unwrap();
                    assert_eq!(data, data2, "expected data to match");
                }
                Message::Unauthenticated(direction, data) => {
                    let (sender, a_in, a_out, receiver): (
                        &mut Sender<mocks::Sink>,
                        &mut mocks::Stream,
                        &mut mocks::Sink,
                        &mut Receiver<mocks::Stream>,
                    ) = match direction {
                        Direction::D2L => (
                            &mut d_sender,
                            &mut adversary_d_stream,
                            &mut adversary_d_sink,
                            &mut l_receiver,
                        ),
                        Direction::L2D => (
                            &mut l_sender,
                            &mut adversary_l_stream,
                            &mut adversary_l_sink,
                            &mut d_receiver,
                        ),
                    };
                    sender.send(&[]).await.unwrap();
                    let _ = recv_frame(a_in, MAX_MESSAGE_SIZE).await.unwrap();
                    send_frame(a_out, &data, MAX_MESSAGE_SIZE).await.unwrap();
                    let res = receiver.recv().await;
                    assert!(res.is_err());
                }
            }
        }
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
