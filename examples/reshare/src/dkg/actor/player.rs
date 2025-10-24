use std::collections::BTreeMap;

use commonware_codec::{Encode, Read};
use commonware_cryptography::{
    bls12381::{
        dkg2::{DealerLog, DealerPrivMsg, DealerPubMsg, Error, Output, Player, RoundInfo},
        primitives::{group::Share, variant::Variant},
    },
    PrivateKey, PublicKey,
};
use commonware_p2p::{Receiver, Sender};
use commonware_runtime::{spawn_cell, ContextCell, Handle, Spawner};
use futures::{
    channel::oneshot::{self, Canceled},
    select_biased, FutureExt,
};

/// The output of a player after finalizing.
///
/// This might contain an error, if the DKG failed, but should otherwise
/// contain the public output of the DKG, and the player's private share.
pub type PlayerOutput<V: Variant, P: PublicKey> = Result<(Output<V, P>, Share), Error>;

struct Message<V: Variant, P: PublicKey> {
    logs: BTreeMap<P, DealerLog<V, P>>,
    cb_in: oneshot::Sender<PlayerOutput<V, P>>,
}

/// A handle to send messages to a [Actor].
pub struct Mailbox<V: Variant, P: PublicKey>(oneshot::Sender<Message<V, P>>);

impl<V, P> Mailbox<V, P>
where
    V: Variant,
    P: PublicKey,
{
    pub async fn finalize(
        self,
        logs: BTreeMap<P, DealerLog<V, P>>,
    ) -> Result<PlayerOutput<V, P>, Canceled> {
        let (cb_in, cb_out) = oneshot::channel();
        self.0.send(Message { logs, cb_in });
        cb_out.await
    }
}

/// The actor for a player in a given round of the DKG.
///
/// This will listen for shares from the dealers.
///
/// At some point, once each dealer has posted their log, you can finalize
/// the player with these logs, and it will post its output and share.
pub struct Actor<E, V, C, S, R>
where
    V: Variant,
    C: PrivateKey,
{
    ctx: ContextCell<E>,
    to_dealers: S,
    from_dealers: R,
    inbox: oneshot::Receiver<Message<V, C::PublicKey>>,
    round_info: RoundInfo<V, C::PublicKey>,
    me: C,
}

impl<E, V, C, S, R> Actor<E, V, C, S, R>
where
    E: Spawner,
    V: Variant,
    C: PrivateKey,
    S: Sender<PublicKey = C::PublicKey>,
    R: Receiver<PublicKey = C::PublicKey>,
{
    /// Create a new [Actor] and its [Mailbox].
    ///
    /// `ctx` is needed for spawning the actor.
    /// `to_dealers` lets us send messages back to the dealers.
    /// `from_dealers` lets us receive messages from the dealers.
    /// `round_info` is the configuration for this round of the DKG.
    /// `me` is the private key identifying this player.
    pub fn new(
        ctx: E,
        to_dealers: S,
        from_dealers: R,
        round_info: RoundInfo<V, C::PublicKey>,
        me: C,
    ) -> (Self, Mailbox<V, C::PublicKey>) {
        let (outbox, inbox) = oneshot::channel();
        let mailbox = Mailbox(outbox);
        let this = Self {
            ctx: ContextCell::new(ctx),
            to_dealers,
            from_dealers,
            inbox,
            round_info,
            me,
        };
        (this, mailbox)
    }

    pub fn start(mut self) -> Handle<()> {
        spawn_cell!(self.ctx, self.run().await)
    }

    async fn run(mut self) {
        let max_read_size = self.round_info.max_read_size();
        let mut player =
            Player::new(self.round_info, self.me).expect("should be able to create player");

        let mut stopped = self.ctx.stopped().fuse();

        // Exiting this loop is stopping the actor.
        loop {
            select_biased! {
                // Context has stopped, so terminate the actor.
                _ = stopped => break,
                // Some dealer sent us a message, or the network is dead.
                msg = self.from_dealers.recv().fuse() => {
                    // The network is dead, just terminate the actor.
                    let Ok((dealer, mut msg_bytes)) = msg else {
                        break;
                    };
                    let Ok((pub_msg, priv_msg)) = <(DealerPubMsg<V>, DealerPrivMsg) as Read>::read_cfg(
                        &mut msg_bytes,
                        &(max_read_size, ()),
                    ) else {
                        // If we can't read the message, ignore it.
                        continue;
                    };
                    if let Some(ack) = player.dealer_message(dealer.clone(), pub_msg, priv_msg) {
                        if self
                            .to_dealers
                            .send(commonware_p2p::Recipients::One(dealer), ack.encode().freeze(), false)
                            .await
                            .is_err()
                        {
                            // If we fail to send a message, terminate the actor.
                            break;
                        }
                    };
                    // Do nothing if we don't produce an ack.
                }
                res = &mut self.inbox => {
                    if let Ok(Message { logs, cb_in }) = res {
                        let _ = cb_in.send(player.finalize(logs));
                    };
                    // Regardless of if we processed the finalizatio, or the inbox is closed,
                    // it's time to terminate the actor.
                    break;
                }
            }
        }
        tracing::debug!("player shutting down");
    }
}
