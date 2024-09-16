use super::Error;
use crate::{Message, Recipients};
use bytes::Bytes;
use commonware_cryptography::{utils::hex, PublicKey};
use rand::{rngs::StdRng, Rng, SeedableRng};
use rand_distr::{Distribution, Normal};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::sync::{mpsc, oneshot, Semaphore};
use tracing::{debug, error};

type Task = (
    PublicKey,
    Recipients,
    Bytes,
    oneshot::Sender<Result<Vec<PublicKey>, Error>>,
);

pub struct Network {
    cfg: Config,

    sender: mpsc::Sender<Task>,
    receiver: mpsc::Receiver<Task>,
    links: HashMap<PublicKey, HashMap<PublicKey, (Link, Arc<Semaphore>)>>,
    agents: HashMap<PublicKey, mpsc::Sender<Message>>,
}

pub struct Link {
    pub latency_mean: f64,   // as ms
    pub latency_stddev: f64, // as ms
    pub success_rate: f64,   // [0,1]

    /// Blocks after this amount (and priority will jump the queue).
    pub outstanding: usize,
}

pub struct Config {
    pub max_message_len: usize,
    pub mailbox_size: usize,
}

impl Network {
    pub fn new(cfg: Config) -> Self {
        let (sender, receiver) = mpsc::channel(cfg.mailbox_size);
        Self {
            cfg,
            sender,
            receiver,
            links: HashMap::new(),
            agents: HashMap::new(),
        }
    }

    /// Link can be called multiple times for the same sender/receiver. The latest
    /// setting will be used.
    pub fn link(&mut self, sender: PublicKey, receiver: PublicKey, config: Link) {
        if sender == receiver {
            panic!("sender and receiver must be different");
        }
        if config.success_rate < 0.0 || config.success_rate > 1.0 {
            panic!("success rate must be in [0,1]");
        }
        let outstanding = config.outstanding;
        self.links
            .entry(sender)
            .or_default()
            .insert(receiver, (config, Arc::new(Semaphore::new(outstanding))));
    }

    pub fn register(&mut self, public_key: PublicKey) -> (Sender, Receiver) {
        let (sender, receiver) = mpsc::channel(self.cfg.mailbox_size);
        self.agents.insert(public_key.clone(), sender);
        (
            Sender::new(public_key, self.sender.clone()),
            Receiver { receiver },
        )
    }

    pub async fn run(mut self) {
        // Initialize RNG
        //
        // TODO: make message sending determinisitic using a single seed (https://www.youtube.com/watch?v=ms8zKpS_dZE)
        let mut rng = StdRng::seed_from_u64(0);

        // Process messages
        while let Some((origin, recipients, message, reply)) = self.receiver.recv().await {
            // Ensure message is valid
            if message.len() > self.cfg.max_message_len {
                if let Err(err) = reply.send(Err(Error::MessageTooLarge(message.len()))) {
                    // This can only happen if the sender exited.
                    error!("failed to send error: {:?}", err);
                }
                continue;
            }

            // Collect recipients
            let recipients = match recipients {
                Recipients::All => self.agents.keys().cloned().collect(),
                Recipients::Some(keys) => keys,
                Recipients::One(key) => vec![key],
            };

            // Send to all recipients
            let mut sent = Vec::new();
            let (acquired_sender, mut acquired_receiver) = mpsc::channel(recipients.len());
            for recipient in recipients {
                // Skip self
                if recipient == origin {
                    debug!("dropping message to {}: self", hex(&recipient));
                    continue;
                }

                // Get sender
                let sender = match self.agents.get(&recipient) {
                    Some(sender) => sender,
                    None => {
                        debug!("dropping message to {}: no agent", hex(&recipient));
                        continue;
                    }
                };

                // Determine if there is a link between the sender and recipient
                let link = match self
                    .links
                    .get(&origin)
                    .and_then(|links| links.get(&recipient))
                {
                    Some(link) => link,
                    None => {
                        debug!("dropping message to {}: no link", hex(&recipient));
                        continue;
                    }
                };

                // Apply link settings
                let success_odds = rng.gen_range(0.0..=1.0);
                let delay = Normal::new(link.0.latency_mean, link.0.latency_stddev)
                    .unwrap()
                    .sample(&mut rng);
                debug!("sending message to {}: delay={}ms", hex(&recipient), delay);

                // Send message
                let task_sender = sender.clone();
                let task_recipient = recipient.clone();
                let task_message = message.clone();
                let task_success_rate = link.0.success_rate;
                let task_semaphore = link.1.clone();
                let task_acquired_sender = acquired_sender.clone();
                tokio::spawn(async move {
                    // Mark as sent as soon as acquire semaphore
                    let _permit = task_semaphore.acquire().await.unwrap();
                    task_acquired_sender.send(()).await.unwrap();

                    // Apply delay to send (once link is not saturated)
                    //
                    // Note: messages can be sent out of order (will not occur when using a
                    // stable TCP connection)
                    tokio::time::sleep(Duration::from_millis(delay as u64)).await;

                    // Drop message if success rate is too low
                    if success_odds > task_success_rate {
                        debug!(
                            "dropping message to {}: random link failure",
                            hex(&task_recipient)
                        );
                        return;
                    }

                    // Send message
                    if let Err(err) = task_sender
                        .send((task_recipient.clone(), task_message))
                        .await
                    {
                        // This can only happen if the receiver exited.
                        error!("failed to send to {}: {:?}", hex(&task_recipient), err);
                    }
                });
                sent.push(recipient);
            }

            // Notify sender of successful sends
            tokio::spawn(async move {
                // Wait for semaphore to be acquired on all sends
                for _ in 0..sent.len() {
                    acquired_receiver.recv().await.unwrap();
                }

                // Notify sender of successful sends
                if let Err(err) = reply.send(Ok(sent)) {
                    // This can only happen if the sender exited.
                    error!("failed to send ack: {:?}", err);
                }
            });
        }
    }
}

#[derive(Clone)]
pub struct Sender {
    me: PublicKey,
    high: mpsc::Sender<Task>,
    low: mpsc::Sender<Task>,
}

impl Sender {
    fn new(me: PublicKey, sender: mpsc::Sender<Task>) -> Self {
        // Listen for messages
        let (high, mut high_receiver) = mpsc::channel(1024);
        let (low, mut low_receiver) = mpsc::channel(1024);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    task = high_receiver.recv() => {
                        if let Err(err) = sender.send(task.unwrap()).await {
                            error!("failed to send high priority task: {:?}", err);
                        }
                    }
                    task = low_receiver.recv() => {
                        if let Err(err) = sender.send(task.unwrap()).await {
                            error!("failed to send low priority task: {:?}", err);
                        }
                    }
                }
            }
        });

        // Return sender
        Self { me, high, low }
    }
}

impl crate::Sender for Sender {
    type Error = Error;

    async fn send(
        &self,
        recipients: Recipients,
        message: Bytes,
        priority: bool,
    ) -> Result<Vec<PublicKey>, Error> {
        let (sender, receiver) = oneshot::channel();
        let channel = if priority { &self.high } else { &self.low };
        channel
            .send((self.me.clone(), recipients, message, sender))
            .await
            .map_err(|_| Error::NetworkClosed)?;
        receiver.await.map_err(|_| Error::NetworkClosed)?
    }
}

pub struct Receiver {
    receiver: mpsc::Receiver<Message>,
}

impl crate::Receiver for Receiver {
    type Error = Error;

    async fn recv(&mut self) -> Result<Message, Error> {
        self.receiver.recv().await.ok_or(Error::NetworkClosed)
    }
}
