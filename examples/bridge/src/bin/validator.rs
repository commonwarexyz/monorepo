use clap::{value_parser, Arg, Command};
use commonware_bridge::{
    application, APPLICATION_NAMESPACE, CONSENSUS_SUFFIX, INDEXER_NAMESPACE, P2P_SUFFIX,
};
use commonware_codec::{Decode, DecodeExt, RangeCfg};
use commonware_consensus::{
    simplex::{self, Engine},
    types::{Epoch, ViewDelta},
};
use commonware_cryptography::{
    bls12381::primitives::{
        group,
        poly::{Poly, Public},
        variant::{MinSig, Variant},
    },
    ed25519, PrivateKeyExt as _, Sha256, Signer as _,
};
use commonware_p2p::{authenticated, Manager};
use commonware_runtime::{buffer::PoolRef, tokio, Metrics, Network, Runner};
use commonware_stream::{dial, Config as StreamConfig};
use commonware_utils::{
    from_hex,
    ordered::{Quorum, Set},
    union, NZUsize, TryCollect, NZU32,
};
use governor::Quota;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
    time::Duration,
};

fn main() {
    // Parse arguments
    let matches = Command::new("validator")
        .about("produce finality certificates and verify external finality certificates")
        .arg(
            Arg::new("bootstrappers")
                .long("bootstrappers")
                .required(false)
                .value_delimiter(',')
                .value_parser(value_parser!(String)),
        )
        .arg(Arg::new("me").long("me").required(true))
        .arg(
            Arg::new("participants")
                .long("participants")
                .required(true)
                .value_delimiter(',')
                .value_parser(value_parser!(u64))
                .help("All participants"),
        )
        .arg(Arg::new("storage-dir").long("storage-dir").required(true))
        .arg(Arg::new("indexer").long("indexer").required(true))
        .arg(Arg::new("identity").long("identity").required(true))
        .arg(Arg::new("share").long("share").required(true))
        .arg(Arg::new("other-public").long("other-public").required(true))
        .get_matches();

    // Create logger
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
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
    tracing::info!(key = ?signer.public_key(), "loaded signer");

    // Configure my port
    let port = parts[1].parse::<u16>().expect("Port not well-formed");
    tracing::info!(port, "loaded port");

    // Configure allowed peers
    let participants = matches
        .get_many::<u64>("participants")
        .expect("Please provide allowed keys")
        .copied();
    if participants.len() == 0 {
        panic!("Please provide at least one participant");
    }
    let validators: Set<_> = participants
        .into_iter()
        .map(|peer| {
            let verifier = ed25519::PrivateKey::from_seed(peer).public_key();
            tracing::info!(key = ?verifier, "registered authorized key");
            verifier
        })
        .try_collect()
        .expect("public keys are unique");

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

    // Configure storage directory
    let storage_directory = matches
        .get_one::<String>("storage-dir")
        .expect("Please provide storage directory");

    // Configure threshold
    let threshold = validators.quorum();
    let identity = matches
        .get_one::<String>("identity")
        .expect("Please provide identity");
    let identity = from_hex(identity).expect("Identity not well-formed");
    let identity: Public<MinSig> =
        Poly::decode_cfg(identity.as_ref(), &RangeCfg::exact(NZU32!(threshold)))
            .expect("Identity not well-formed");
    let share = matches
        .get_one::<String>("share")
        .expect("Please provide share");
    let share = from_hex(share).expect("Share not well-formed");
    let share = group::Share::decode(share.as_ref()).expect("Share not well-formed");

    // Configure indexer
    let indexer = matches
        .get_one::<String>("indexer")
        .expect("Please provide indexer");
    let parts = indexer.split('@').collect::<Vec<&str>>();
    let indexer_key = parts[0]
        .parse::<u64>()
        .expect("Indexer key not well-formed");
    let indexer = ed25519::PrivateKey::from_seed(indexer_key).public_key();
    let indexer_address = SocketAddr::from_str(parts[1]).expect("Indexer address not well-formed");

    // Configure other public
    let other_public = matches
        .get_one::<String>("other-public")
        .expect("Please provide other public");
    let other_public = from_hex(other_public).expect("Other identity not well-formed");
    let other_public = <MinSig as Variant>::Public::decode(other_public.as_ref())
        .expect("Other identity not well-formed");

    // Initialize context
    let runtime_cfg = tokio::Config::new().with_storage_directory(storage_directory);
    let executor = tokio::Runner::new(runtime_cfg);

    // Configure indexer
    let indexer_cfg = StreamConfig {
        signing_key: signer.clone(),
        namespace: INDEXER_NAMESPACE.to_vec(),
        max_message_size: 1024 * 1024,
        synchrony_bound: Duration::from_secs(1),
        max_handshake_age: Duration::from_secs(60),
        handshake_timeout: Duration::from_secs(5),
    };

    // Configure network
    let p2p_cfg = authenticated::discovery::Config::local(
        signer,
        &union(APPLICATION_NAMESPACE, P2P_SUFFIX),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
        bootstrapper_identities.clone(),
        1024 * 1024, // 1MB
    );

    // Start context
    executor.start(|context| async move {
        // Dial indexer
        let (sink, stream) = context
            .dial(indexer_address)
            .await
            .expect("Failed to dial indexer");
        let indexer = dial(
            context.with_label("dialer"),
            indexer_cfg,
            indexer,
            stream,
            sink,
        )
        .await
        .expect("Failed to upgrade connection with indexer");

        // Setup p2p
        let (mut network, mut oracle) =
            authenticated::discovery::Network::new(context.with_label("network"), p2p_cfg);

        // Provide authorized peers
        //
        // In a real-world scenario, this would be updated as new peer sets are created (like when
        // the composition of a validator set changes).
        oracle.update(0, validators.clone()).await;

        // Register consensus channels
        //
        // If you want to maximize the number of views per second, increase the rate limit
        // for this channel.
        let (vote_sender, vote_receiver) = network.register(
            0,
            Quota::per_second(NZU32!(10)),
            256, // 256 messages in flight
        );
        let (certificate_sender, certificate_receiver) = network.register(
            1,
            Quota::per_second(NZU32!(10)),
            256, // 256 messages in flight
        );
        let (resolver_sender, resolver_receiver) = network.register(
            2,
            Quota::per_second(NZU32!(10)),
            256, // 256 messages in flight
        );

        // Initialize application
        let consensus_namespace = union(APPLICATION_NAMESPACE, CONSENSUS_SUFFIX);
        let (application, scheme, mailbox) = application::Application::new(
            context.with_label("application"),
            application::Config {
                indexer,
                namespace: consensus_namespace.clone(),
                identity,
                other_public,
                hasher: Sha256::default(),
                mailbox_size: 1024,
                participants: validators.clone(),
                share,
            },
        );

        // Initialize consensus
        let engine = Engine::new(
            context.with_label("engine"),
            simplex::Config {
                scheme,
                blocker: oracle,
                automaton: mailbox.clone(),
                relay: mailbox.clone(),
                reporter: mailbox.clone(),
                partition: String::from("log"),
                mailbox_size: 1024,
                epoch: Epoch::zero(),
                namespace: consensus_namespace,
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                leader_timeout: Duration::from_secs(1),
                notarization_timeout: Duration::from_secs(2),
                nullify_retry: Duration::from_secs(10),
                fetch_timeout: Duration::from_secs(1),
                activity_timeout: ViewDelta::new(10),
                skip_timeout: ViewDelta::new(5),
                fetch_concurrent: 32,
                fetch_rate_per_peer: Quota::per_second(NZU32!(1)),
                buffer_pool: PoolRef::new(NZUsize!(16_384), NZUsize!(10_000)),
            },
        );

        // Start consensus
        network.start();
        engine.start(
            (vote_sender, vote_receiver),
            (certificate_sender, certificate_receiver),
            (resolver_sender, resolver_receiver),
        );

        // Block on application
        application.run().await;
    });
}
