use commonware_codec::{Encode, ReadExt as _};
use commonware_cryptography::{
    bls12381::{
        dkg2::{Dealer, DealerPrivMsg, DealerPubMsg, PlayerAck, RoundInfo, SignedDealerLog},
        primitives::{group::Share, variant::Variant},
    },
    transcript::Transcript,
    PrivateKey,
};
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{spawn_cell, Clock, ContextCell, Handle, Metrics, Spawner, Storage};
use futures::{
    channel::{
        mpsc,
        oneshot::{self, Canceled},
    },
    select_biased, FutureExt, SinkExt, StreamExt,
};
use rand_core::CryptoRngCore;
use std::collections::BTreeMap;

mod state;
use state::State;

enum Message<V: Variant, C: PrivateKey> {
    Transmit,
    Finalize {
        cb_in: oneshot::Sender<SignedDealerLog<V, C>>,
    },
}

/// A handle to send messages to an [Actor].
pub struct Mailbox<V: Variant, C: PrivateKey>(mpsc::Sender<Message<V, C>>);

impl<V: Variant, C: PrivateKey> Mailbox<V, C> {
    pub async fn finalize(mut self) -> Result<SignedDealerLog<V, C>, Canceled> {
        let (cb_in, cb_out) = oneshot::channel();
        self.0.send(Message::Finalize { cb_in }).await;
        cb_out.await
    }

    pub async fn transmit(&mut self) -> Result<(), Canceled> {
        self.0.send(Message::Transmit).await.map_err(|_| Canceled)
    }
}

/// An actor for a dealer in the DKG.
///
/// This actor generates shares to distribute to other players, and then collects
/// signed acknowledgements from them, which it gathers into a final log to
/// put on chain.
pub struct Actor<E, V, C, S, R>
where
    E: Clock + Storage + Metrics,
    V: Variant,
    C: PrivateKey,
{
    ctx: ContextCell<E>,
    state: State<E, C::PublicKey>,
    to_players: S,
    from_players: R,
    inbox: mpsc::Receiver<Message<V, C>>,
    dealer: Dealer<V, C>,
    pub_msg: DealerPubMsg<V>,
    unsent_priv_msgs: BTreeMap<C::PublicKey, DealerPrivMsg>,
}

impl<E, V, C, S, R> Actor<E, V, C, S, R>
where
    E: Clock + Storage + Metrics + Spawner + CryptoRngCore,
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
    pub async fn init(
        ctx: E,
        storage_partition: String,
        to_players: S,
        from_players: R,
        round_info: RoundInfo<V, C::PublicKey>,
        me: C,
        share: Share,
    ) -> (Self, Mailbox<V, C>) {
        let mut state = State::load::<V>(
            ctx.with_label("storage"),
            storage_partition,
            round_info.round(),
            round_info.max_read_size(),
        )
        .await;
        let mut ctx = ContextCell::new(ctx);
        let (outbox, inbox) = mpsc::channel(1);
        let mailbox = Mailbox(outbox);

        let (dealer, pub_msg, priv_msgs) = Dealer::start(
            Transcript::resume(state.seed(ctx.as_mut()).await).noise(b"dealer rng"),
            round_info,
            me,
            Some(share),
        )
        .expect("should be able to create dealer");

        let mut this = Self {
            ctx,
            state,
            to_players,
            from_players,
            inbox,
            dealer,
            pub_msg,
            unsent_priv_msgs: priv_msgs.into_iter().collect(),
        };

        for (player, ack) in this.state.acks().iter().cloned().collect::<Vec<_>>() {
            this.ack(true, player.clone(), ack.clone()).await;
        }

        (this, mailbox)
    }

    pub fn start(mut self) -> Handle<()> {
        spawn_cell!(self.ctx, self.run().await)
    }

    async fn run(mut self) {
        let mut stopped = self.ctx.stopped().fuse();
        let finalize = loop {
            select_biased! {
                // If the context has stopped, terminate.
                _ = stopped => break None,
                msg = self.from_players.recv().fuse() => {
                    let Ok((player, mut msg_bytes)) = msg else {
                        // The network is dead, so terminate.
                        break None;
                    };
                    let Ok(ack) = PlayerAck::<C::PublicKey>::read(&mut msg_bytes) else {
                        continue;
                    };
                    self.ack(false, player, ack).await;
                }
                res = self.inbox.next() => {
                    let Some(msg) = res else {
                        break None;
                    };
                    match msg {
                        Message::Transmit => {
                            if self.transmit().await.is_err() {
                                break None;
                            }
                        },
                        Message::Finalize { cb_in } => {
                            break Some(cb_in);
                        }
                    }
                }
            }
        };
        if let Some(cb_in) = finalize {
            self.finalize(cb_in);
        }
        tracing::debug!("dealer shutting down");
    }

    async fn ack(&mut self, replay: bool, player: C::PublicKey, ack: PlayerAck<C::PublicKey>) {
        if !self.unsent_priv_msgs.contains_key(&player) {
            return;
        }
        if let Err(e) = self.dealer.receive_player_ack(player.clone(), ack.clone()) {
            tracing::info!("bad player ack: {}", e);
            return;
        }
        self.unsent_priv_msgs.remove(&player);
        if !replay {
            self.state.put_ack(player, ack).await;
        }
    }

    async fn transmit(&mut self) -> Result<(), S::Error> {
        for (target, priv_msg) in &self.unsent_priv_msgs {
            self.to_players
                .send(
                    Recipients::One(target.clone()),
                    (self.pub_msg.clone(), priv_msg.clone()).encode().freeze(),
                    false,
                )
                .await?;
        }
        Ok(())
    }

    fn finalize(self, cb_in: oneshot::Sender<SignedDealerLog<V, C>>) {
        let log = self.dealer.finalize();
        let _ = cb_in.send(log);
    }
}
