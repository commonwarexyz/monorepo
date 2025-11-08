//! Demonstrate collecting responses from multiple nodes using commonware-collector and commonware-p2p.
//!
//! This example shows how to use `commonware-collector` to send queries to multiple nodes and
//! collect their responses. One node acts as an **originator** that sends queries, while other
//! nodes act as **handlers** that process queries and send responses back.
//!
//! # Usage (3 Nodes)
//!
//! _To run this example, you must first install [Rust](https://www.rust-lang.org/tools/install)._
//!
//! ## Node 1 (Originator - Bootstrapper)
//!
//! ```sh
//! cargo run --release -- --me=1@3001 --participants=1,2,3 --role=originator
//! ```
//!
//! ## Node 2 (Handler)
//!
//! ```sh
//! cargo run --release -- --me=2@3002 --participants=1,2,3 --role=handler --bootstrappers=1@127.0.0.1:3001
//! ```
//!
//! ## Node 3 (Handler)
//!
//! ```sh
//! cargo run --release -- --me=3@3003 --participants=1,2,3 --role=handler --bootstrappers=1@127.0.0.1:3001
//! ```

mod types;

use clap::{value_parser, Arg, Command};
use commonware_collector::p2p::{Config, Engine, Mailbox};
use commonware_collector::{Handler, Monitor, Originator};
use commonware_cryptography::{ed25519, PrivateKeyExt as _, Signer as _};
use commonware_p2p::{authenticated::discovery, Manager, Recipients};
use commonware_runtime::{tokio, Clock, Metrics, Runner, Spawner};
use commonware_utils::{set::Ordered, NZU32};
use futures::channel::oneshot;
use governor::Quota;
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
    sync::Arc,
    time::Duration,
};
use async_lock::Mutex;
use tracing::{info, warn};
use types::{Query, QueryResult};

/// Unique namespace to avoid message replay attacks.
const APPLICATION_NAMESPACE: &[u8] = b"commonware-collector-demo";

/// Handler that processes queries and sends responses.
#[derive(Clone)]
struct QueryHandler {
    node_id: u64,
}

impl Handler for QueryHandler {
    type PublicKey = ed25519::PublicKey;
    type Request = Query;
    type Response = QueryResult;

    async fn process(
        &mut self,
        origin: Self::PublicKey,
        request: Query,
        responder: oneshot::Sender<Self::Response>,
    ) {
        info!(
            node_id = self.node_id,
            origin = ?origin,
            query_id = request.id,
            value = request.value,
            "received query"
        );

        // Process the query: multiply the value by 2 and add node_id
        let result = request.value.wrapping_mul(2).wrapping_add(self.node_id as u32);

        let response = QueryResult {
            id: request.id,
            result,
            node_id: self.node_id,
        };

        info!(
            node_id = self.node_id,
            query_id = request.id,
            result = response.result,
            "sending response"
        );

        // Send the response
        if let Err(_) = responder.send(response) {
            warn!(node_id = self.node_id, "failed to send response");
        }
    }
}

/// Monitor that tracks collected responses.
#[derive(Clone)]
struct ResponseMonitor {
    node_id: u64,
    collected: Arc<Mutex<HashMap<u64, Vec<(ed25519::PublicKey, QueryResult)>>>>,
}

impl ResponseMonitor {
    fn new(node_id: u64) -> Self {
        Self {
            node_id,
            collected: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl Monitor for ResponseMonitor {
    type PublicKey = ed25519::PublicKey;
    type Response = QueryResult;

    async fn collected(
        &mut self,
        handler: Self::PublicKey,
        response: Self::Response,
        count: usize,
    ) {
        info!(
            node_id = self.node_id,
            handler = ?handler,
            query_id = response.id,
            result = response.result,
            count,
            "collected response"
        );

        let mut collected = self.collected.lock().await;
        collected
            .entry(response.id)
            .or_insert_with(Vec::new)
            .push((handler, response));
    }
}

/// Send queries periodically and display collected responses.
async fn run_originator<E>(
    context: E,
    mut mailbox: Mailbox<ed25519::PublicKey, Query>,
    handlers: Ordered<ed25519::PublicKey>,
) where
    E: Clock + Spawner,
{
    info!("starting originator");

    let mut query_id = 0u64;
    loop {
        context.sleep(Duration::from_secs(5)).await;

        query_id += 1;
        let value = (query_id % 1000) as u32;
        let query = Query {
            id: query_id,
            value,
        };

        info!(
            query_id,
            value,
            handlers_count = handlers.len(),
            "sending query to all handlers"
        );

        // Send query to all handlers
        let recipients = if handlers.len() == 1 {
            Recipients::One(handlers.iter().next().unwrap().clone())
        } else {
            Recipients::Some(handlers.iter().cloned().collect())
        };
        match mailbox.send(recipients, query).await
        {
            Ok(sent_to) => {
                info!(
                    query_id,
                    sent_to_count = sent_to.len(),
                    "query sent successfully"
                );
            }
            Err(e) => {
                warn!(?e, "failed to send query");
                continue;
            }
        }

        // Wait a bit for responses to arrive
        context.sleep(Duration::from_secs(2)).await;
    }
}

fn main() {
    // Initialize context
    let executor = tokio::Runner::default();

    // Parse arguments
    let matches = Command::new("commonware-collector-demo")
        .about("demonstrate collecting responses from multiple nodes")
        .arg(Arg::new("me").long("me").required(true))
        .arg(
            Arg::new("participants")
                .long("participants")
                .required(true)
                .value_delimiter(',')
                .value_parser(value_parser!(u64)),
        )
        .arg(
            Arg::new("role")
                .long("role")
                .required(true)
                .value_parser(["originator", "handler"])
                .help("Role: 'originator' sends queries, 'handler' processes queries"),
        )
        .arg(
            Arg::new("bootstrappers")
                .long("bootstrappers")
                .required(false)
                .value_delimiter(',')
                .value_parser(value_parser!(String)),
        )
        .get_matches();

    // Create logger
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    // Configure my identity
    let me = matches
        .get_one::<String>("me")
        .expect("Please provide identity");
    let parts = me.split('@').collect::<Vec<&str>>();
    if parts.len() != 2 {
        panic!("Identity not well-formed");
    }
    let key = parts[0].parse::<u64>().expect("Key not well-formed");
    let signer = ed25519::PrivateKey::from_seed(key);
    info!(key = ?signer.public_key(), "loaded signer");

    // Configure my port
    let port = parts[1].parse::<u16>().expect("Port not well-formed");
    info!(port, "loaded port");

    // Configure allowed peers
    let participants = matches
        .get_many::<u64>("participants")
        .expect("Please provide participants")
        .copied();
    if participants.len() == 0 {
        panic!("Please provide at least one participant");
    }
    let recipients = participants
        .into_iter()
        .map(|peer| {
            let verifier = ed25519::PrivateKey::from_seed(peer).public_key();
            info!(key = ?verifier, "registered authorized key");
            verifier
        })
        .collect::<Ordered<_>>();

    // Configure bootstrappers (if provided)
    let bootstrappers = matches.get_many::<String>("bootstrappers");
    let mut bootstrapper_identities = Vec::new();
    if let Some(bootstrappers) = bootstrappers {
        for bootstrapper in bootstrappers {
            let parts = bootstrapper.split('@').collect::<Vec<&str>>();
            let bootstrapper_key = parts[0]
                .parse::<u64>()
                .expect("Bootstrapper key not well-formed");
            let verifier = ed25519::PrivateKey::from_seed(bootstrapper_key).public_key();
            let bootstrapper_address =
                SocketAddr::from_str(parts[1]).expect("Bootstrapper address not well-formed");
            bootstrapper_identities.push((verifier, bootstrapper_address));
        }
    }

    // Get role
    let role = matches
        .get_one::<String>("role")
        .expect("Please provide role");

    // Configure network
    const MAX_MESSAGE_SIZE: usize = 1024;
    let p2p_cfg = discovery::Config::local(
        signer.clone(),
        APPLICATION_NAMESPACE,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
        bootstrapper_identities.clone(),
        MAX_MESSAGE_SIZE,
    );

    // Start context
    executor.start(|context| async move {
        // Initialize network
        let (mut network, mut oracle) =
            discovery::Network::new(context.with_label("network"), p2p_cfg);

        // Provide authorized peers
        oracle.update(0, recipients.clone()).await;

        // Register channels for collector
        let (request_sender, request_receiver) = network.register(
            0,
            Quota::per_second(NZU32!(128)),
            256,
        );
        let (response_sender, response_receiver) = network.register(
            1,
            Quota::per_second(NZU32!(128)),
            256,
        );

        // Start network
        let network_handler = network.start();

        // Both originator and handler need monitor and handler
        let monitor = ResponseMonitor::new(key);
        let handler = QueryHandler { node_id: key };

        // Oracle implements Blocker trait directly
        let blocker = oracle;
        let cfg = Config {
            blocker,
            monitor: monitor.clone(),
            handler,
            mailbox_size: 256,
            priority_request: false,
            request_codec: (),
            priority_response: false,
            response_codec: (),
        };

        let (engine, mailbox) = Engine::new(context.with_label("engine"), cfg);
        engine.start(
            (request_sender, request_receiver),
            (response_sender, response_receiver),
        );

        if role == "originator" {
            // Get handlers (all participants except self)
            let handlers: Ordered<_> = recipients
                .iter()
                .filter(|&pk| *pk != signer.public_key())
                .cloned()
                .collect();

            // Run originator in a separate task
            let originator_context = context.with_label("originator");
            originator_context.spawn(move |context| {
                run_originator(context, mailbox, handlers)
            });
        } else {
            info!("handler started, waiting for queries...");
        }

        // Keep running
        network_handler.await.expect("Network failed");
    });
}
