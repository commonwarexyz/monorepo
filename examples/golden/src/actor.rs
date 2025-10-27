use std::time::Duration;

use crate::dkg::broadcast::BroadcastMsg;
use crate::dkg::participant::Participant;
use crate::error::Error;
use crate::greetings::{GreetingsMsg, PendingGreetings};
use bytes::Bytes;
use commonware_codec::{Encode, RangeCfg, Read};
use commonware_cryptography::bls12381::PublicKey;
use commonware_macros::select;
use commonware_p2p::Recipients;
use commonware_p2p::{Receiver, Sender};
use commonware_runtime::tokio::Context;
use commonware_runtime::Spawner;
use commonware_runtime::{spawn_cell, Clock, ContextCell, Handle};
use commonware_utils::set::Ordered;
use rand::thread_rng;
use tracing::{debug, error, info, trace};

pub struct Actor {
    ctx: ContextCell<Context>,
    participant: Participant,
    players: Ordered<PublicKey>,
    player_id: u32,
    greetings: PendingGreetings,
    t: usize,
}

impl Actor {
    pub fn new(
        ctx: Context,
        participant: Participant,
        players: Ordered<PublicKey>,
        player_id: u32,
        t: usize,
    ) -> Self {
        Self {
            ctx: ContextCell::new(ctx),
            participant,
            greetings: PendingGreetings::default(),
            player_id,
            players,
            t,
        }
    }

    pub fn start(
        mut self,
        dkg_network: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        greet_network: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
    ) -> Handle<Result<(), Error>> {
        spawn_cell!(self.ctx, self.run(dkg_network, greet_network).await)
    }

    pub async fn broadcast_shares<S: Sender<PublicKey = PublicKey>>(
        &self,
        msg: BroadcastMsg,
        sender_dkg: &mut S,
    ) -> Result<(), S::Error> {
        let res = sender_dkg
            .send(Recipients::All, msg.encode().into(), false)
            .await?;
        trace!(target:"dealer", "Shares sent to {res:?}");
        Ok(())
    }

    pub async fn send_greetings<S: Sender<PublicKey = PublicKey>>(
        &mut self,
        sender_greet: &mut S,
    ) -> Result<GreetingsMsg, S::Error> {
        let secret_share = self
            .participant
            .get_share()
            .expect("secret share not ready");
        let greet = GreetingsMsg::new(self.player_id, secret_share);
        let res = sender_greet
            .send(Recipients::All, greet.encode().into(), false)
            .await?;
        trace!(target:"player", "Greetings sent to {res:?}");
        Ok(greet)
    }

    pub fn on_incoming_bmsg(&mut self, sender: PublicKey, mut msg: Bytes) -> Result<(), Error> {
        let cfg = (
            RangeCfg::new(0..=1024),               // max msg length
            RangeCfg::new(0..=self.players.len()), // max shares count
            self.t,
        );
        let bmsg = BroadcastMsg::read_cfg(&mut msg, &cfg)?;
        self.participant
            .on_incoming_bmsg(&sender, self.player_id, bmsg, &self.players)?;
        Ok(())
    }

    pub fn on_incoming_greetings(
        &mut self,
        sender: PublicKey,
        mut msg: Bytes,
    ) -> Result<(), Error> {
        let greet = GreetingsMsg::read_cfg(&mut msg, &())?;
        let Some(pubkey_shares) = self.participant.pubkey_shares() else {
            debug!(
                sender = sender.to_string(),
                "Received greetings while dkg is not completed yet, ignoring..."
            );
            return Ok(());
        };
        self.greetings.try_apply_greetings(greet, pubkey_shares)?;
        Ok(())
    }

    pub async fn run(
        mut self,
        dkg_network: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        greet_network: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
    ) -> Result<(), Error> {
        let (mut sender_dkg, mut receiver_dkg) = dkg_network;
        let (mut sender_greet, mut receiver_greet) = greet_network;

        let mut next_tick = self.ctx.current() + Duration::from_secs(5);

        // Generate shares once, at the beginning
        let bmsg = self
            .participant
            .generate_bmsg(&mut thread_rng(), self.players.clone());

        // Update local registry with own share
        let pki = self.participant.pk_i().clone();
        self.participant
            .on_incoming_bmsg(&pki, self.player_id, bmsg.clone(), &self.players)
            .expect("Error processing own share");

        loop {
            select! {
                res =receiver_dkg.recv()=>{
                    let Ok((sender, msg)) = res else {
                        error!(target:"player","Error receiving msg: {}", res.unwrap_err());
                        continue;
                    };
                    let res = self.on_incoming_bmsg(sender, msg);

                    if let Err(e) = res{
                        error!(target:"player","Error on incoming bmsg: {e}");
                        continue;
                    };
                },

                res =receiver_greet.recv()=>{
                    let Ok((sender, msg)) = res else {
                        error!(target:"player","Error receiving msg: {}", res.unwrap_err());
                        continue;
                    };
                    let res = self.on_incoming_greetings(sender, msg);

                    if let Err(e) = res{
                        error!(target:"player","Error on incoming greetings: {e}");
                        continue;
                    };
                },

                _= self.ctx.sleep_until(next_tick)=>{
                    next_tick = self.ctx.current() + Duration::from_secs(1);
                    if let Err(e)=self.broadcast_shares(bmsg.clone(), &mut sender_dkg).await{
                        error!(target:"player","Error sending message: {e}");
                    }
                },
            }

            let dkg_completed = self.participant.is_ready();
            if !dkg_completed {
                continue;
            }
            let group = self
                .participant
                .get_group_pubkey()
                .expect("Group key not ready");
            info!(target:"player", "Group public key is ready: {group}");

            let greet = self
                .send_greetings(&mut sender_greet)
                .await
                .inspect_err(|e| error!("Error sending greetings: {e}"))
                .unwrap();
            let pukey_shares = self
                .participant
                .pubkey_shares()
                .expect("Pubkey shares not ready");
            self.greetings
                .try_apply_greetings(greet, pukey_shares)
                .inspect_err(|e| error!("Error Applying greetings: {e}"))
                .unwrap();

            if self.greetings.len() >= self.t {
                self.greetings
                    .verify_threshod_signature(self.t as u32, group.as_ref())
                    .inspect_err(|e| error!("Error verifying threshold signature: {e}"))
                    .unwrap();
                return Ok(());
            }
        }
    }
}
