use std::collections::BTreeMap;

use commonware_codec::{Encode, Read};
use commonware_cryptography::{
    bls12381::{
        dkg2::{
            DealerLog, DealerPrivMsg, DealerPubMsg, Error, Output, Player, PlayerAck, RoundInfo,
        },
        primitives::{group::Share, variant::Variant},
    },
    PrivateKey, PublicKey,
};
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{spawn_cell, ContextCell, Handle, Spawner};
use futures::{
    channel::{
        mpsc,
        oneshot::{self, Canceled},
    },
    select_biased, FutureExt, SinkExt as _, StreamExt as _,
};

/// The output of a player after finalizing.
///
/// This might contain an error, if the DKG failed, but should otherwise
/// contain the public output of the DKG, and the player's private share.
pub type PlayerOutput<V: Variant, P: PublicKey> = Result<(Output<V, P>, Share), Error>;

enum Message<V: Variant, P: PublicKey> {
    Transmit,
    Finalize {
        logs: BTreeMap<P, DealerLog<V, P>>,
        cb_in: oneshot::Sender<PlayerOutput<V, P>>,
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
        self.0.send(Message::Finalize { logs, cb_in });
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
    inbox: mpsc::Receiver<Message<V, C::PublicKey>>,
    max_read_size: usize,
    player: Player<V, C>,
    acks: BTreeMap<C::PublicKey, PlayerAck<C::PublicKey>>,
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
        let (outbox, inbox) = mpsc::channel(1);
        let mailbox = Mailbox(outbox);

        let max_read_size = round_info.max_read_size();
        let player = Player::new(round_info, me).expect("should be able to create player");
        let this = Self {
            ctx: ContextCell::new(ctx),
            to_dealers,
            from_dealers,
            inbox,
            max_read_size,
            player,
            acks: BTreeMap::new(),
        };
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
                        &(self.max_read_size, ()),
                    ) else {
                        // If we can't read the message, ignore it.
                        continue;
                    };
                    self.dealer_message(dealer, pub_msg, priv_msg).await;
                }
                res = self.inbox.next() => {
                    let Some(msg) = res else {
                        break None;
                    };
                    match msg {
                        Message::Transmit => if self.transmit().await.is_err() {
                            break None;
                        },
                        Message::Finalize { logs, cb_in } => break Some((logs, cb_in)),
                    }
                }
            }
        };
        if let Some((logs, cb_in)) = finalize {
            self.finalize(logs, cb_in);
        }
        tracing::debug!("player shutting down");
    }

    async fn dealer_message(
        &mut self,
        dealer: C::PublicKey,
        pub_msg: DealerPubMsg<V>,
        priv_msg: DealerPrivMsg,
    ) {
        if let Some(ack) = self
            .player
            .dealer_message(dealer.clone(), pub_msg, priv_msg)
        {
            self.acks.insert(dealer, ack);
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
        cb_in: oneshot::Sender<PlayerOutput<V, C::PublicKey>>,
    ) {
        let _ = cb_in.send(self.player.finalize(logs));
    }
}
