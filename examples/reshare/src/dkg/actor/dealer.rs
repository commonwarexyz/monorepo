use commonware_codec::{Encode, ReadExt as _};
use commonware_cryptography::{
    bls12381::{
        dkg2::{Dealer, PlayerAck, RoundInfo, SignedDealerLog},
        primitives::{group::Share, variant::Variant},
    },
    PrivateKey,
};
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{spawn_cell, ContextCell, Handle, Spawner};
use futures::{
    channel::oneshot::{self, Canceled},
    select_biased, FutureExt,
};
use rand_core::CryptoRngCore;

struct Message<V: Variant, C: PrivateKey> {
    cb_in: oneshot::Sender<SignedDealerLog<V, C>>,
}

/// A handle to send messages to an [Actor].
pub struct Mailbox<V: Variant, C: PrivateKey>(oneshot::Sender<Message<V, C>>);

impl<V: Variant, C: PrivateKey> Mailbox<V, C> {
    pub async fn finalize(self) -> Result<SignedDealerLog<V, C>, Canceled> {
        let (cb_in, cb_out) = oneshot::channel();
        self.0.send(Message { cb_in });
        cb_out.await
    }
}

/// An actor for a dealer in the DKG.
///
/// This actor generates shares to distribute to other players, and then collects
/// signed acknowledgements from them, which it gathers into a final log to
/// put on chain.
pub struct Actor<E, V, C, S, R>
where
    V: Variant,
    C: PrivateKey,
{
    ctx: ContextCell<E>,
    to_players: S,
    from_players: R,
    inbox: oneshot::Receiver<Message<V, C>>,
    round_info: RoundInfo<V, C::PublicKey>,
    me: C,
    share: Share,
}

impl<E, V, C, S, R> Actor<E, V, C, S, R>
where
    E: Spawner + CryptoRngCore,
    V: Variant,
    C: PrivateKey,
    S: Sender<PublicKey = C::PublicKey>,
    R: Receiver<PublicKey = C::PublicKey>,
{
    /// Create an [Actor] and its [Mailbox].
    ///
    /// `ctx` lets us spawn the actor, and provides randomness.
    /// `to_players` lets us send messages to the players.
    /// `from_players` lets us receive messages from the players.
    /// `round_info` is the configuration for the round.
    /// `me` is the private key identifying the dealer.
    /// `share` is the previous share for the dealer.
    pub fn new(
        ctx: E,
        to_players: S,
        from_players: R,
        round_info: RoundInfo<V, C::PublicKey>,
        me: C,
        share: Share,
    ) -> (Self, Mailbox<V, C>) {
        let (outbox, inbox) = oneshot::channel();
        let mailbox = Mailbox(outbox);
        let this = Self {
            ctx: ContextCell::new(ctx),
            to_players,
            from_players,
            inbox,
            round_info,
            me,
            share,
        };
        (this, mailbox)
    }

    pub fn start(mut self) -> Handle<()> {
        spawn_cell!(self.ctx, self.run().await)
    }

    async fn run(mut self) {
        let (mut dealer, pub_msg, priv_msgs) = Dealer::start(
            self.ctx.as_mut(),
            self.round_info,
            self.me,
            Some(self.share),
        )
        .expect("should be able to create dealer");
        // For borrow checker reasons, we can't do this concurrently,
        // so we just send out the messages serially.
        for (target, priv_msg) in priv_msgs {
            self.to_players
                .send(
                    Recipients::One(target),
                    (pub_msg.clone(), priv_msg).encode().freeze(),
                    false,
                )
                .await;
        }

        let mut stopped = self.ctx.stopped().fuse();
        // Exiting the loop terminates thea ctor.
        loop {
            select_biased! {
                // If the context has stopped, terminate.
                _ = stopped => break,
                msg = self.from_players.recv().fuse() => {
                    let Ok((player, mut msg_bytes)) = msg else {
                        // The network is dead, so terminate.
                        break;
                    };
                    let _ = PlayerAck::<C::PublicKey>::read(&mut msg_bytes)
                        .ok()
                        .and_then(|ack| dealer.receive_player_ack(player, ack).ok());
                }
                res = &mut self.inbox => {
                    if let Ok(Message { cb_in }) = res {
                        let log = dealer.finalize();
                        let _ = cb_in.send(log);
                    };
                    // Regardless of if the inbox is dead, we terminate now.
                    break;
                }
            }
        }
        tracing::debug!("dealer shutting down");
    }
}
