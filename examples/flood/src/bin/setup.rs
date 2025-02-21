use axum::{routing::get, serve, Extension, Router};
use clap::{value_parser, Arg, Command};
use commonware_cryptography::{
    ed25519::{PrivateKey, PublicKey},
    Ed25519, Scheme,
};
use commonware_deployer::Peers;
use commonware_p2p::{authenticated, Receiver, Recipients, Sender};
use commonware_runtime::{
    tokio::{self, Executor},
    Network, Runner, Spawner,
};
use commonware_utils::{from_hex_formatted, union};
use futures::future::try_join_all;
use governor::Quota;
use prometheus_client::{encoding::text::encode, registry::Registry};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    num::NonZeroU32,
    str::FromStr,
    sync::{Arc, Mutex},
};
use tracing::{error, info, Level};

fn main() {
    // Parse arguments
    let matches = Command::new("setup")
        .about("generate configuration files")
        .arg(
            Arg::new("peers")
                .required(true)
                .value_parser(value_parser!(usize)),
        )
        .arg(
            Arg::new("regions")
                .required(true)
                .value_delimiter(',')
                .value_parser(value_parser!(String)),
        )
        .arg(
            Arg::new("instance_type")
                .required(true)
                .value_parser(value_parser!(String)),
        )
        .get_matches();
}
