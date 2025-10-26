use std::time::Duration;

use crate::dkg::broadcast::BroadcastMsg;
use crate::dkg::error::Error;
use crate::dkg::participant::Participant;
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
use tracing::{debug, error, info};
pub struct Actor {
    ctx: ContextCell<Context>,
    participant: Participant,
    players: Ordered<PublicKey>,
    player_id: u32,
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
            player_id,
            players,
            t,
        }
    }

    pub fn start(
        mut self,
        sender: impl Sender<PublicKey = PublicKey>,
        receiver: impl Receiver<PublicKey = PublicKey>,
    ) -> Handle<()> {
        spawn_cell!(self.ctx, self.run(sender, receiver).await)
    }

    pub async fn broadcast_shares<S: Sender<PublicKey = PublicKey>>(
        &mut self,
        msg: BroadcastMsg,
        sender: &mut S,
    ) -> Result<(), S::Error> {
        let res = sender
            .send(Recipients::All, msg.encode().into(), false)
            .await?;

        // Update local registry with own share
        let pki = self.participant.pk_i().clone();
        self.participant
            .on_incoming_bmsg(&pki, self.player_id, msg, &self.players)
            .expect("Error processing own share");

        debug!(target:"dealer", "Shares received by {res:?}");

        Ok(())
    }

    pub fn on_incoming_msg(&mut self, sender: PublicKey, mut msg: Bytes) -> Result<(), Error> {
        let cfg = (
            RangeCfg::new(0..=1024),               // max msg length
            RangeCfg::new(0..=self.players.len()), // max shares count
            self.t,
        );
        let bmsg = BroadcastMsg::read_cfg(&mut msg, &cfg)?;
        self.participant
            .on_incoming_bmsg(&sender, self.player_id, bmsg, &self.players)?;
        if let Some(group) = self.participant.get_group_pubkey() {
            info!(target:"player", "Group public key is ready: {group}")
        }
        Ok(())
    }

    pub async fn run(
        mut self,
        mut sender: impl Sender<PublicKey = PublicKey>,
        mut receiver: impl Receiver<PublicKey = PublicKey>,
    ) {
        let mut next_tick = self.ctx.current() + Duration::from_secs(5);

        // Generate shares once, at the beginning
        let bmsg = self
            .participant
            .generate_bmsg(&mut thread_rng(), self.players.clone());

        loop {
            select! {

                res =receiver.recv()=>{
                    let Ok((sender, msg)) = res else {
                        error!(target:"player","Error receiving msg: {}", res.unwrap_err());
                        continue;
                    };
                    if let Err(e) = self.on_incoming_msg(sender, msg){
                        error!(target:"player","Error on incoming msg: {e}");
                    }
                },
                _= self.ctx.sleep_until(next_tick)=>{
                    next_tick = self.ctx.current() + Duration::from_secs(5);
                    if let Err(e)=self.broadcast_shares(bmsg.clone(), &mut sender).await{
                        error!(target:"player","Error sending message: {e}");
                    }
                },

            }
        }
    }
}
