//! Deploy infrastructure across cloud providers.
//!
//! `commonware-deployer` is a library and CLI that automates the deployment of infrastructure across
//! different cloud providers. `commonware-deployer` is frequently used to bridge the gap between
//! local deployment (TODO).
//!
//! # Installation
//!
//! ## Local
//!
//! ```bash
//! cargo install --path . --force
//! ```
//!
//! ## Crates.io
//!
//! ```bash
//! cargo install commonware-deployer
//! ```
//!
//! # Commands
//!
//! ## `deployer ec2`
//!
//! ### `deployer ec2 create`
//!
//! Deploy EC2 instances across multiple regions from a YAML configuration file.
//!
//! ### `deployer ec2 update`
//!
//! Update binary and configuration files in-place on all instances (instead of redeploying).
//!
//! ### `deployer ec2 destroy`
//!
//! Destroy all resources associated with a given deployment.

pub mod ec2;
