mod admission;
mod http;

use admission::{PairingPolicy, UpgradeAdmission, unix_seconds};
use commonware_browser_p2p_service::{EmbeddedAssets, PairingPayload, PairingStore};
use commonware_cryptography::{Signer as _, ed25519};
use commonware_math::algebra::Random as _;
use commonware_p2p::{Receiver as _, Recipients, Sender as _};
use commonware_runtime::{
    Acceptor as _, Listener as _, Quota, Runner as _, Spawner as _, Supervisor as _,
    TcpListener as _, tokio as commonware_tokio,
};
use commonware_stream::encrypted;
use commonware_websocket::{WebSocketAcceptor, WebSocketConfig};
use qrcode::{QrCode, render::unicode};
use std::{
    collections::HashSet,
    error::Error,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    num::{NonZeroU32, NonZeroUsize},
    time::Duration,
};
use tokio::net::TcpListener;

const CHAT_CHANNEL: u64 = 0;
const CHAT_NAMESPACE: &[u8] = b"_COMMONWARE_BROWSER_P2P_CHAT";
const MAX_CHAT_MESSAGE_SIZE: usize = 16 * 1024;
const MAX_NETWORK_MESSAGE_SIZE: u32 = 64 * 1024;
const INVITE_LIFETIME: Duration = Duration::from_secs(5 * 60);

fn main() -> Result<(), Box<dyn Error>> {
    let host = advertised_host()?;
    commonware_tokio::Runner::default().start(|context| run(context, host))
}

async fn run(mut context: commonware_tokio::Context, host: IpAddr) -> Result<(), Box<dyn Error>> {
    let signer = ed25519::PrivateKey::random(&mut context);
    let desktop_public_key = signer.public_key();
    let store = PairingStore::default();
    let now = unix_seconds();
    let invite = store.create(now + INVITE_LIFETIME.as_secs(), now)?;

    let websocket = WebSocketAcceptor::new(
        WebSocketConfig {
            max_message_size: MAX_NETWORK_MESSAGE_SIZE as usize,
            ..WebSocketConfig::default()
        },
        UpgradeAdmission::new(store.clone()),
    )?;
    let mut websocket_listener = websocket
        .bind(&SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        .await?;
    let websocket_address = websocket_listener.local_addr()?;

    // The WebSocket acceptor owns upgraded connections and cannot also return ordinary HTTP
    // responses, so static assets use a separate ephemeral listener.
    let http_listener =
        TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)).await?;
    let http_address = http_listener.local_addr()?;

    let websocket_url = format!("ws://{host}:{}/pair", websocket_address.port());
    let payload = PairingPayload::new(desktop_public_key.as_ref(), websocket_url, &invite);
    let payload_json = payload.compact_json()?;
    let invite_url = http::public_url(host, http_address, &payload.encoded()?);
    print_invite(&payload_json, &invite_url)?;

    let (admitted_sender, mut admitted_receiver) = tokio::sync::mpsc::channel(16);

    let stream = encrypted::Config {
        signing_key: signer,
        namespace: CHAT_NAMESPACE.to_vec(),
        max_message_size: MAX_NETWORK_MESSAGE_SIZE,
        synchrony_bound: Duration::from_secs(5),
        max_handshake_age: Duration::from_secs(10),
        handshake_timeout: Duration::from_secs(10),
    };
    let config = commonware_p2p::authenticated::lookup::AttachmentConfig {
        stream,
        admission: PairingPolicy::new(admitted_sender),
        mailbox_size: NonZeroUsize::new(256).unwrap(),
        send_batch_size: NonZeroUsize::new(8).unwrap(),
        ping_frequency: Duration::from_secs(15),
        tracked_peer_sets: NonZeroUsize::new(1).unwrap(),
        peer_connection_cooldown: Duration::ZERO,
        block_duration: Duration::from_secs(30),
    };
    let (mut network, _oracle, attachments) =
        commonware_p2p::authenticated::lookup::AttachmentNetwork::new(
            context.child("network"),
            config,
        );
    let (mut chat_sender, mut chat_receiver) = network.register(
        CHAT_CHANNEL,
        Quota::per_second(NonZeroU32::new(128).unwrap()),
        256,
    );
    let _network = network.start();

    let _http = context.child("http").spawn(|_| async move {
        if let Err(error) = http::serve(http_listener).await {
            eprintln!("asset server stopped: {error}");
        }
    });
    let _accept = context.child("accept").spawn(|context| async move {
        loop {
            let connection = match websocket_listener.accept().await {
                Ok(connection) => connection,
                Err(error) => {
                    eprintln!("WebSocket accept failed: {error}");
                    continue;
                }
            };
            let attachments = attachments.clone();
            context.child("connection").spawn(|_| async move {
                if let Err(error) = attachments.attach_inbound(connection).await {
                    eprintln!("authenticated connection rejected: {error}");
                }
            });
        }
    });

    let mut chat_peers = HashSet::new();
    loop {
        tokio::select! {
            Some(peer) = admitted_receiver.recv() => {
                println!("Browser joined as {peer}. Generating the next one-time invite.");
                let now = unix_seconds();
                let invite = store.create(now + INVITE_LIFETIME.as_secs(), now)?;
                let websocket_url = format!("ws://{host}:{}/pair", websocket_address.port());
                let payload = PairingPayload::new(
                    desktop_public_key.as_ref(),
                    websocket_url,
                    &invite,
                );
                let payload_json = payload.compact_json()?;
                let invite_url = http::public_url(host, http_address, &payload.encoded()?);
                print_invite(&payload_json, &invite_url)?;
            }
            result = chat_receiver.recv() => {
                let (peer, message) = result?;
                if message.len() > MAX_CHAT_MESSAGE_SIZE {
                    eprintln!("ignored oversized chat message from {peer}");
                    continue;
                }
                let Ok(text) = std::str::from_utf8(message.as_ref()) else {
                    eprintln!("ignored non-UTF-8 chat message from {peer}");
                    continue;
                };
                println!("{peer}: {text}");

                chat_peers.insert(peer.clone());
                let recipients = chat_peers
                    .iter()
                    .filter(|candidate| **candidate != peer)
                    .cloned()
                    .collect::<Vec<_>>();
                if recipients.is_empty() {
                    continue;
                }

                let mut relayed = Vec::with_capacity(peer.as_ref().len() + message.len());
                relayed.extend_from_slice(peer.as_ref());
                relayed.extend_from_slice(message.as_ref());
                let _ = chat_sender.send(Recipients::Some(recipients), relayed, false);
            }
            result = tokio::signal::ctrl_c() => {
                result?;
                return Ok(());
            }
        }
    }
}

fn advertised_host() -> Result<IpAddr, Box<dyn Error>> {
    let mut arguments = std::env::args().skip(1);
    if let Some(argument) = arguments.next() {
        if argument != "--host" {
            return Err(format!("unknown argument {argument:?}; expected --host <LAN-IP>").into());
        }
        let host = arguments
            .next()
            .ok_or("--host requires an IP address")?
            .parse()?;
        if arguments.next().is_some() {
            return Err("unexpected arguments after --host <LAN-IP>".into());
        }
        return Ok(host);
    }

    let host = local_ip_address::local_ip()?;
    if host.is_loopback() {
        return Err("could not discover a LAN address; pass --host <LAN-IP>".into());
    }
    Ok(host)
}

fn print_invite(payload: &str, invite_url: &str) -> Result<(), Box<dyn Error>> {
    let qr = QrCode::new(invite_url.as_bytes())?
        .render::<unicode::Dense1x2>()
        .quiet_zone(true)
        .build();
    println!("Open the QR URL on the phone, or paste the pairing payload into the app.");
    println!("Asset URL: {invite_url}");
    println!("Pairing payload (shown once; expires in 5 minutes):\n{payload}");
    println!("{qr}");
    if !EmbeddedAssets::is_embedded() {
        eprintln!(
            "No frontend assets are embedded. Build ../browser before rebuilding the service."
        );
    }
    Ok(())
}
