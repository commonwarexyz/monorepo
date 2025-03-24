//! Deploy infrastructure across cloud providers.
//!
//! `commonware-deployer` automates the deployment of infrastructure across different cloud providers, closing the gap
//! between a local demo and remote deployment. `commonware-deployer` is both available as a CLI tool for standard
//! operation and as a library for custom workflows.
//!
//! # CLI Installation
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
//! # CLI Commands
//!
//! _While the crate is named `commonware-deployer`, the CLI is named `deployer`._
//!
//! ## `ec2`
//!
//! Deploy a custom binary (and configuration) to any number of EC2 instances across multiple regions. Collect
//! metrics and logs from all instances via a private network.
//!
//! ### `create`
//!
//! Deploy EC2 instances across multiple regions from a YAML configuration file.
//!
//! ### `update`
//!
//! Update binaries (and configurations) in-place on all instances.
//!
//! ### `authorize`
//!
//! Add the deployer's current IP (or the one provided) to all security groups.
//!
//! ### `destroy`
//!
//! Destroy all resources associated with a given deployment.

pub mod ec2;
