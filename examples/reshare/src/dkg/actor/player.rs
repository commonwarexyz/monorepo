use crate::dkg::state::State;
use commonware_codec::{Encode, Read};
use commonware_consensus::types::Epoch;
use commonware_cryptography::{
    bls12381::{
        dkg::{DealerLog, DealerPrivMsg, DealerPubMsg, Error, Info, Output, Player, PlayerAck},
        primitives::{group::Share, variant::Variant},
    },
    PublicKey, Signer,
};
use commonware_macros::select_loop;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{spawn_cell, Clock, ContextCell, Handle, Metrics, Spawner, Storage};
use futures::{
    channel::{
        mpsc,
        oneshot::{self, Canceled},
    },
    SinkExt as _, StreamExt as _,
};
use std::{collections::BTreeMap, num::NonZeroU32};
use tracing::debug;

/// The output of a player after finalizing.
///
/// This might contain an error, if the DKG failed, but should otherwise
/// contain the public output of the DKG, and the player's private share.
pub type PlayerOutput<V, P> = Result<(Output<V, P>, Share), Error>;

enum Message<V: Variant, P: PublicKey> {
    Transmit,
    Finalize {
        logs: BTreeMap<P, DealerLog<V, P>>,
        output: oneshot::Sender<PlayerOutput<V, P>>,
    },
}

/// A handle to send messages to a [Actor].
pub struct Mailbox<V: Variant, P: PublicKey>(mpsc::Sender<Message<V, P>>);

impl<V, P> Mailbox<V, P>
where
    V: Variant,
    P: PublicKey,
{
    pub async fn transmit(&mut self) -> Result<(), Canceled> {
        self.0.send(Message::Transmit).await.map_err(|_| Canceled)
    }

    pub async fn finalize(
        mut self,
        logs: BTreeMap<P, DealerLog<V, P>>,
    ) -> Result<PlayerOutput<V, P>, Canceled> {
        let (cb_in, cb_out) = oneshot::channel();
        self.0
            .send(Message::Finalize {
                logs,
                output: cb_in,
            })
            .await
            .map_err(|_| Canceled)?;
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
    E: Clock + Storage + Metrics,
    V: Variant,
    C: Signer,
{
    ctx: ContextCell<E>,
    epoch: Epoch,
    max_read_size: NonZeroU32,
    state: State<E, V, C::PublicKey>,
    to_dealers: S,
    from_dealers: R,
    inbox: mpsc::Receiver<Message<V, C::PublicKey>>,
    player: Player<V, C>,
    acks: BTreeMap<C::PublicKey, PlayerAck<C::PublicKey>>,
}

impl<E, V, C, S, R> Actor<E, V, C, S, R>
where
    E: Clock + Storage + Metrics + Spawner,
    V: Variant,
    C: Signer,
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
    pub async fn init(
        ctx: E,
        state: State<E, V, C::PublicKey>,
        to_dealers: S,
        from_dealers: R,
        round_info: Info<V, C::PublicKey>,
        max_read_size: NonZeroU32,
        me: C,
    ) -> (Self, Mailbox<V, C::PublicKey>) {
        let (outbox, inbox) = mpsc::channel(1);
        let mailbox = Mailbox(outbox);

        let me_pk = me.public_key();
        let player = Player::new(round_info.clone(), me)
            .unwrap_or_else(|_| panic!("should be able to create player {me_pk:?}"));
        let epoch = Epoch::new(round_info.round());
        let replay = state.dealer_msgs(epoch).await;
        let mut this = Self {
            ctx: ContextCell::new(ctx),
            epoch,
            state,
            max_read_size,
            to_dealers,
            from_dealers,
            inbox,
            player,
            acks: BTreeMap::new(),
        };

        for (dealer, pub_msg, priv_msg) in replay {
            this.dealer_message(true, dealer, pub_msg, priv_msg).await;
        }

        (this, mailbox)
    }

    pub fn start(mut self) -> Handle<()> {
        spawn_cell!(self.ctx, self.run().await)
    }

    async fn run(mut self) {
        let mut finalize = None;
        // Exiting this loop is stopping the actor.
        select_loop! {
            self.ctx,
            // Context has stopped, so terminate the actor.
            on_stopped => {
                break;
            },
            // Some dealer sent us a message, or the network is dead.
            msg = self.from_dealers.recv() => {
                // The network is dead, just terminate the actor.
                let Ok((dealer, mut msg_bytes)) = msg else {
                    break;
                };
                let Ok((pub_msg, priv_msg)) = <(DealerPubMsg<V>, DealerPrivMsg) as Read>::read_cfg(
                    &mut msg_bytes,
                    &(self.max_read_size, ()),
                ) else {
                    // If we can't read the message, ignore it.
                    continue;
                };
                self.dealer_message(false, dealer, pub_msg, priv_msg).await;
            },
            res = self.inbox.next() => {
                let Some(msg) = res else {
                    break;
                };
                match msg {
                    Message::Transmit => if self.transmit().await.is_err() {
                        break;
                    },
                    Message::Finalize { logs, output } => {
                        finalize = Some((logs, output));
                        break;
                    }
                }
            }
        }
        // We need to keep this around until after finalize
        let epoch = self.epoch;
        if let Some((logs, cb_in)) = finalize {
            self.finalize(logs, cb_in);
        }
        debug!(?epoch, "player shutting down");
    }

    async fn dealer_message(
        &mut self,
        replay: bool,
        dealer: C::PublicKey,
        pub_msg: DealerPubMsg<V>,
        priv_msg: DealerPrivMsg,
    ) {
        if let Some(ack) =
            self.player
                .dealer_message(dealer.clone(), pub_msg.clone(), priv_msg.clone())
        {
            self.acks.insert(dealer.clone(), ack);
            if !replay {
                self.state
                    .append_dealer_msg(self.epoch, dealer, pub_msg, priv_msg)
                    .await;
            }
        };
    }

    async fn transmit(&mut self) -> Result<(), S::Error> {
        for (dealer, ack) in &self.acks {
            self.to_dealers
                .send(
                    Recipients::One(dealer.clone()),
                    ack.encode().freeze(),
                    false,
                )
                .await?;
        }
        Ok(())
    }

    fn finalize(
        self,
        logs: BTreeMap<C::PublicKey, DealerLog<V, C::PublicKey>>,
        output: oneshot::Sender<PlayerOutput<V, C::PublicKey>>,
    ) {
        // We get asked by the DKG actor to finalize, and we use the
        // callback they provide to return the answer. If the callback
        // has been dropped on their end, then no one cares about this answer
        // anymore, and we can die in peace.
        let _ = output.send(self.player.finalize(logs, 1));
    }
}
