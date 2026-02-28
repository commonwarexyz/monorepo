//! Codec wrapper for [Sender] and [Receiver].

use crate::{CheckedSender, Receiver, Recipients, Sender};
use bytes::Bytes;
use commonware_codec::{Codec, Error};
use std::{any::Any, sync::Arc, time::SystemTime};

// Message tracking for fuzzing (when MSG_INFO=1 is set)
#[cfg(feature = "fuzzing")]
mod msg_tracking {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    };

    static MESSAGE_COUNTER: AtomicUsize = AtomicUsize::new(0);
    static MESSAGE_LENGTHS: Mutex<Vec<usize>> = Mutex::new(Vec::new());
    static INIT: std::sync::Once = std::sync::Once::new();

    pub fn track_message(len: usize) {
        INIT.call_once(|| {
            if std::env::var("MSG_INFO").is_ok() {
                extern "C" fn report_at_exit() {
                    let count = MESSAGE_COUNTER.load(Ordering::SeqCst);
                    if count > 0 {
                        eprintln!("MSG_COUNT:{}", count);
                        let lengths = MESSAGE_LENGTHS.lock().unwrap();
                        eprintln!("MSG_LENGTHS:{:?}", *lengths);
                    }
                }
                unsafe { libc::atexit(report_at_exit) };
            }
        });
        MESSAGE_COUNTER.fetch_add(1, Ordering::SeqCst);
        MESSAGE_LENGTHS.lock().unwrap().push(len);
    }
}

// FFI hooks for message corruption (optionally provided by commonware-fuzz crate)
// Uses weak linkage - if commonware-fuzz is linked, it provides the implementation
// Otherwise, None (no corruption)
#[cfg(feature = "fuzzing")]
extern "C" {
    #[linkage = "extern_weak"]
    static commonware_fuzz_corrupt_bytes: Option<unsafe extern "C" fn(*mut u8, usize) -> bool>;

    #[linkage = "extern_weak"]
    static commonware_fuzz_should_corrupt_msg: Option<unsafe extern "C" fn() -> bool>;

    #[linkage = "extern_weak"]
    static commonware_fuzz_get_fuzz_input: Option<unsafe extern "C" fn(*mut u8, usize) -> usize>;
}

#[cfg(feature = "fuzzing")]
#[inline(always)]
fn corrupt_bytes_hook(msg: &mut [u8]) {
    unsafe {
        if let Some(corrupt_fn) = commonware_fuzz_corrupt_bytes {
            corrupt_fn(msg.as_mut_ptr(), msg.len());
        }
    }
}

/// Wrap a [Sender] and [Receiver] with some [Codec].
pub fn wrap<S: Sender, R: Receiver, V: Codec>(
    config: V::Cfg,
    sender: S,
    receiver: R,
) -> (WrappedSender<S, V>, WrappedReceiver<R, V>) {
    (
        WrappedSender::new(sender),
        WrappedReceiver::new(config, receiver),
    )
}

/// Tuple representing a message received from a given public key.
pub type WrappedMessage<P, V> = (P, Result<V, Error>);

/// Wrapper around a [Sender] that encodes messages using a [Codec].
#[derive(Clone)]
pub struct WrappedSender<S: Sender, V: Codec> {
    sender: S,

    _phantom_v: std::marker::PhantomData<V>,
}

impl<S: Sender, V: Codec> WrappedSender<S, V> {
    /// Create a new [WrappedSender] with the given [Sender].
    pub const fn new(sender: S) -> Self {
        Self {
            sender,
            _phantom_v: std::marker::PhantomData,
        }
    }

    /// Send a message to a set of recipients.
    pub async fn send(
        &mut self,
        recipients: Recipients<S::PublicKey>,
        mut message: V,
        priority: bool,
    ) -> Result<Vec<S::PublicKey>, <S::Checked<'_> as CheckedSender>::Error> {
        #[cfg(feature = "fuzzing")]
        let encoded = {
            let mut encoded = message.encode().to_vec();
            msg_tracking::track_message(encoded.len());
            // Optionally corrupt the message
            corrupt_bytes_hook(&mut encoded);
            encoded
        };

        #[cfg(not(feature = "fuzzing"))]
        let encoded = message.encode();

        self.sender
            .send(recipients, Bytes::from(encoded), priority)
            .await
    }

    /// Check recipients and return a rate-limited sender for them.
    pub async fn check<'a>(
        &'a mut self,
        recipients: Recipients<S::PublicKey>,
    ) -> Result<S::Checked<'a>, SystemTime> {
        self.sender.check(recipients).await
    }
}

/// Wrapper around a [Receiver] that decodes messages using a [Codec].
pub struct WrappedReceiver<R: Receiver, V: Codec> {
    config: V::Cfg,
    receiver: R,

    _phantom_v: std::marker::PhantomData<V>,
}

impl<R: Receiver, V: Codec> WrappedReceiver<R, V> {
    /// Create a new [WrappedReceiver] with the given [Receiver].
    pub const fn new(config: V::Cfg, receiver: R) -> Self {
        Self {
            config,
            receiver,
            _phantom_v: std::marker::PhantomData,
        }
    }

    /// Receive a message from an arbitrary recipient.
    pub async fn recv(&mut self) -> Result<WrappedMessage<R::PublicKey, V>, R::Error> {
        let (pk, bytes) = self.receiver.recv().await?;
        let decoded = match V::decode_cfg(bytes.as_ref(), &self.config) {
            Ok(decoded) => decoded,
            Err(e) => {
                return Ok((pk, Err(e)));
            }
        };
        Ok((pk, Ok(decoded)))
    }
}
