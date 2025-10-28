use commonware_codec::{Encode, Read};
use commonware_cryptography::{
    bls12381::{
        dkg2::{
            DealerLog, DealerPrivMsg, DealerPubMsg, Error, Output, Player, PlayerAck, RoundInfo,
            SignedDealerLog,
        },
        primitives::{group::Share, variant::Variant},
    },
    PrivateKey,
};
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{spawn_cell, Clock, ContextCell, Handle, Metrics, Spawner, Storage};
use futures::{
    channel::{
        mpsc,
        oneshot::{self, Canceled},
    },
    select_biased, FutureExt, SinkExt as _, StreamExt as _,
};
use std::collections::BTreeMap;

mod state;
use state::State;

/// The output of a player after finalizing.
///
/// This might contain an error, if the DKG failed, but should otherwise
/// contain the public output of the DKG, and the player's private share.
pub type PlayerOutput<V, P> = Result<(Output<V, P>, Share), Error>;

enum Message<V: Variant, S: PrivateKey> {
    Transmit,
    Log {
        log: SignedDealerLog<V, S>,
    },
    Finalize {
        cb_in: oneshot::Sender<PlayerOutput<V, S::PublicKey>>,
    },
}

/// A handle to send messages to a [Actor].
pub struct Mailbox<V: Variant, S: PrivateKey>(mpsc::Sender<Message<V, S>>);

impl<V, S> Mailbox<V, S>
where
    V: Variant,
    S: PrivateKey,
{
    pub async fn transmit(&mut self) -> Result<(), Canceled> {
        self.0.send(Message::Transmit).await.map_err(|_| Canceled)
    }

    pub async fn log(&mut self, log: SignedDealerLog<V, S>) -> Result<(), Canceled> {
        self.0
            .send(Message::Log { log })
            .await
            .map_err(|_| Canceled)
    }

    pub async fn finalize(mut self) -> Result<PlayerOutput<V, S::PublicKey>, Canceled> {
        let (cb_in, cb_out) = oneshot::channel();
        self.0
            .send(Message::Finalize { cb_in })
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
    C: PrivateKey,
{
    ctx: ContextCell<E>,
    state: State<E, V, C::PublicKey>,
    to_dealers: S,
    from_dealers: R,
    inbox: mpsc::Receiver<Message<V, C>>,
    round_info: RoundInfo<V, C::PublicKey>,
    player: Player<V, C>,
    acks: BTreeMap<C::PublicKey, PlayerAck<C::PublicKey>>,
    logs: BTreeMap<C::PublicKey, DealerLog<V, C::PublicKey>>,
}

impl<E, V, C, S, R> Actor<E, V, C, S, R>
where
    E: Clock + Storage + Metrics + Spawner,
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
    pub async fn init(
        ctx: E,
        storage_partition: String,
        to_dealers: S,
        from_dealers: R,
        round_info: RoundInfo<V, C::PublicKey>,
        me: C,
    ) -> (Self, Mailbox<V, C>) {
        let state = State::load(
            ctx.with_label("storage"),
            storage_partition,
            round_info.round(),
            round_info.max_read_size(),
        )
        .await;

        let (outbox, inbox) = mpsc::channel(1);
        let mailbox = Mailbox(outbox);

        let player = Player::new(round_info.clone(), me).expect("should be able to create player");

        let mut this = Self {
            ctx: ContextCell::new(ctx),
            state,
            to_dealers,
            from_dealers,
            inbox,
            round_info,
            player,
            acks: BTreeMap::new(),
            logs: BTreeMap::new(),
        };

        let priv_msgs = this.state.msgs().iter().cloned().collect::<Vec<_>>();
        for (dealer, pub_msg, priv_msg) in priv_msgs {
            this.dealer_message(true, dealer, pub_msg, priv_msg).await;
        }
        let logs = this.state.logs().iter().cloned().collect::<Vec<_>>();
        for (dealer, log) in logs {
            this.dealer_log(true, dealer, log).await;
        }

        (this, mailbox)
    }

    pub fn start(mut self) -> Handle<()> {
        spawn_cell!(self.ctx, self.run().await)
    }

    async fn run(mut self) {
        let mut stopped = self.ctx.stopped().fuse();
        // Exiting this loop is stopping the actor.
        let finalize = loop {
            select_biased! {
                // Context has stopped, so terminate the actor.
                _ = stopped => break None,
                // Some dealer sent us a message, or the network is dead.
                msg = self.from_dealers.recv().fuse() => {
                    // The network is dead, just terminate the actor.
                    let Ok((dealer, mut msg_bytes)) = msg else {
                        break None;
                    };
                    let Ok((pub_msg, priv_msg)) = <(DealerPubMsg<V>, DealerPrivMsg) as Read>::read_cfg(
                        &mut msg_bytes,
                        &(self.round_info.max_read_size(), ()),
                    ) else {
                        // If we can't read the message, ignore it.
                        continue;
                    };
                    self.dealer_message(false, dealer, pub_msg, priv_msg).await;
                }
                res = self.inbox.next() => {
                    let Some(msg) = res else {
                        break None;
                    };
                    match msg {
                        Message::Transmit => if self.transmit().await.is_err() {
                            break None;
                        },
                        Message::Log { log } => if let Some((dealer, log)) = log.check(&self.round_info) {
                            self.dealer_log(false, dealer, log).await;
                        },
                        Message::Finalize { cb_in } => break Some(cb_in),
                    }
                }
            }
        };
        if let Some(cb_in) = finalize {
            self.finalize(cb_in);
        }
        tracing::debug!("player shutting down");
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
                self.state.put_msg(dealer, pub_msg, priv_msg).await;
            }
        };
    }

    async fn dealer_log(
        &mut self,
        replay: bool,
        dealer: C::PublicKey,
        log: DealerLog<V, C::PublicKey>,
    ) {
        if self.logs.contains_key(&dealer) {
            return;
        }
        self.logs.insert(dealer.clone(), log.clone());
        if !replay {
            self.state.put_log(dealer, log).await;
        }
    }

    async fn transmit(&mut self) -> Result<(), S::Error> {
        for (dealer, ack) in &self.acks {
            // Don't transmit logs to dealers that have already finalized.
            if self.logs.contains_key(dealer) {
                continue;
            }
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

    fn finalize(self, cb_in: oneshot::Sender<PlayerOutput<V, C::PublicKey>>) {
        let _ = cb_in.send(self.player.finalize(self.logs));
    }
}
