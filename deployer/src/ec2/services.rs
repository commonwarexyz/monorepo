//! Service configuration for Prometheus, Loki, Grafana, Promtail, and a caller-provided binary

use crate::ec2::{
    s3::{S3_DEPLOYMENTS_PREFIX, S3_TOOLS_BINARIES_PREFIX, S3_TOOLS_CONFIGS_PREFIX},
    Architecture,
};
use commonware_macros::ready;

/// Deployer version used to namespace static configs in S3
const DEPLOYER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Version of Prometheus to download and install
pub const PROMETHEUS_VERSION: &str = "3.2.0";

/// Version of Promtail to download and install
pub const PROMTAIL_VERSION: &str = "3.4.2";

/// Version of Node Exporter to download and install
pub const NODE_EXPORTER_VERSION: &str = "1.9.0";

/// Version of Loki to download and install
pub const LOKI_VERSION: &str = "3.4.2";

/// Version of Tempo to download and install
pub const TEMPO_VERSION: &str = "2.7.1";

/// Version of Pyroscope to download and install
pub const PYROSCOPE_VERSION: &str = "1.12.0";

/// Version of Grafana to download and install
pub const GRAFANA_VERSION: &str = "11.5.2";

// S3 key functions for tool binaries
//
// Convention: {S3_TOOLS_BINARIES_PREFIX}/{tool}/{version}/{platform}/{filename}
//
// The filename matches the upstream download URL exactly. The version is placed
// in the path (not embedded in the filename) to ensure consistent cache organization
// across all tools, since some upstream releases include version in the filename
// (e.g., prometheus-3.2.0.linux-arm64.tar.gz) while others do not
// (e.g., loki-linux-arm64.zip).

pub(crate) fn prometheus_bin_s3_key(version: &str, architecture: Architecture) -> String {
    format!(
        "{S3_TOOLS_BINARIES_PREFIX}/prometheus/{version}/linux-{arch}/prometheus-{version}.linux-{arch}.tar.gz",
        arch = architecture.as_str()
    )
}

pub(crate) fn grafana_bin_s3_key(version: &str, architecture: Architecture) -> String {
    format!(
        "{S3_TOOLS_BINARIES_PREFIX}/grafana/{version}/linux-{arch}/grafana_{version}_{arch}.deb",
        arch = architecture.as_str()
    )
}

pub(crate) fn loki_bin_s3_key(version: &str, architecture: Architecture) -> String {
    format!(
        "{S3_TOOLS_BINARIES_PREFIX}/loki/{version}/linux-{arch}/loki-linux-{arch}.zip",
        arch = architecture.as_str()
    )
}

pub(crate) fn pyroscope_bin_s3_key(version: &str, architecture: Architecture) -> String {
    format!(
        "{S3_TOOLS_BINARIES_PREFIX}/pyroscope/{version}/linux-{arch}/pyroscope_{version}_linux_{arch}.tar.gz",
        arch = architecture.as_str()
    )
}

pub(crate) fn tempo_bin_s3_key(version: &str, architecture: Architecture) -> String {
    format!(
        "{S3_TOOLS_BINARIES_PREFIX}/tempo/{version}/linux-{arch}/tempo_{version}_linux_{arch}.tar.gz",
        arch = architecture.as_str()
    )
}

pub(crate) fn node_exporter_bin_s3_key(version: &str, architecture: Architecture) -> String {
    format!(
        "{S3_TOOLS_BINARIES_PREFIX}/node-exporter/{version}/linux-{arch}/node_exporter-{version}.linux-{arch}.tar.gz",
        arch = architecture.as_str()
    )
}

pub(crate) fn promtail_bin_s3_key(version: &str, architecture: Architecture) -> String {
    format!(
        "{S3_TOOLS_BINARIES_PREFIX}/promtail/{version}/linux-{arch}/promtail-linux-{arch}.zip",
        arch = architecture.as_str()
    )
}

// S3 key functions for component configs and services (include deployer version for cache invalidation)
//
// Convention: {S3_TOOLS_CONFIGS_PREFIX}/{deployer_version}/{component}/{file}

#[ready(0)]
pub fn prometheus_service_s3_key() -> String {
    format!("{S3_TOOLS_CONFIGS_PREFIX}/{DEPLOYER_VERSION}/prometheus/service")
}

#[ready(0)]
pub fn grafana_datasources_s3_key() -> String {
    format!("{S3_TOOLS_CONFIGS_PREFIX}/{DEPLOYER_VERSION}/grafana/datasources.yml")
}

#[ready(0)]
pub fn grafana_dashboards_s3_key() -> String {
    format!("{S3_TOOLS_CONFIGS_PREFIX}/{DEPLOYER_VERSION}/grafana/all.yml")
}

#[ready(0)]
pub fn loki_config_s3_key() -> String {
    format!("{S3_TOOLS_CONFIGS_PREFIX}/{DEPLOYER_VERSION}/loki/config.yml")
}

#[ready(0)]
pub fn loki_service_s3_key() -> String {
    format!("{S3_TOOLS_CONFIGS_PREFIX}/{DEPLOYER_VERSION}/loki/service")
}

#[ready(0)]
pub fn pyroscope_config_s3_key() -> String {
    format!("{S3_TOOLS_CONFIGS_PREFIX}/{DEPLOYER_VERSION}/pyroscope/config.yml")
}

#[ready(0)]
pub fn pyroscope_service_s3_key() -> String {
    format!("{S3_TOOLS_CONFIGS_PREFIX}/{DEPLOYER_VERSION}/pyroscope/service")
}

#[ready(0)]
pub fn tempo_config_s3_key() -> String {
    format!("{S3_TOOLS_CONFIGS_PREFIX}/{DEPLOYER_VERSION}/tempo/config.yml")
}

#[ready(0)]
pub fn tempo_service_s3_key() -> String {
    format!("{S3_TOOLS_CONFIGS_PREFIX}/{DEPLOYER_VERSION}/tempo/service")
}

#[ready(0)]
pub fn node_exporter_service_s3_key() -> String {
    format!("{S3_TOOLS_CONFIGS_PREFIX}/{DEPLOYER_VERSION}/node-exporter/service")
}

#[ready(0)]
pub fn promtail_service_s3_key() -> String {
    format!("{S3_TOOLS_CONFIGS_PREFIX}/{DEPLOYER_VERSION}/promtail/service")
}

// S3 key functions for pyroscope agent (lives with pyroscope component)

#[ready(0)]
pub fn pyroscope_agent_service_s3_key() -> String {
    format!("{S3_TOOLS_CONFIGS_PREFIX}/{DEPLOYER_VERSION}/pyroscope/agent.service")
}

#[ready(0)]
pub fn pyroscope_agent_timer_s3_key() -> String {
    format!("{S3_TOOLS_CONFIGS_PREFIX}/{DEPLOYER_VERSION}/pyroscope/agent.timer")
}

// S3 key functions for system configs

#[ready(0)]
pub fn bbr_config_s3_key() -> String {
    format!("{S3_TOOLS_CONFIGS_PREFIX}/{DEPLOYER_VERSION}/system/bbr.conf")
}

#[ready(0)]
pub fn logrotate_config_s3_key() -> String {
    format!("{S3_TOOLS_CONFIGS_PREFIX}/{DEPLOYER_VERSION}/system/logrotate.conf")
}

// S3 key functions for binary instance configs

pub(crate) fn binary_service_s3_key_for_arch(architecture: Architecture) -> String {
    format!(
        "{S3_TOOLS_CONFIGS_PREFIX}/{DEPLOYER_VERSION}/binary/service-{arch}",
        arch = architecture.as_str()
    )
}

/// Returns the S3 key for an instance's binary by digest (deduplicated within deployment)
#[ready(0)]
pub fn binary_s3_key(tag: &str, digest: &str) -> String {
    format!("{S3_DEPLOYMENTS_PREFIX}/{tag}/binaries/{digest}")
}

/// Returns the S3 key for an instance's config by digest (deduplicated within deployment)
#[ready(0)]
pub fn config_s3_key(tag: &str, digest: &str) -> String {
    format!("{S3_DEPLOYMENTS_PREFIX}/{tag}/configs/{digest}")
}

/// Returns the S3 key for hosts.yaml by digest (deduplicated within deployment)
#[ready(0)]
pub fn hosts_s3_key(tag: &str, digest: &str) -> String {
    format!("{S3_DEPLOYMENTS_PREFIX}/{tag}/hosts/{digest}")
}

/// Returns the S3 key for promtail config by digest (deduplicated within deployment)
#[ready(0)]
pub fn promtail_s3_key(tag: &str, digest: &str) -> String {
    format!("{S3_DEPLOYMENTS_PREFIX}/{tag}/promtail/{digest}")
}

/// Returns the S3 key for pyroscope agent script by digest (deduplicated within deployment)
#[ready(0)]
pub fn pyroscope_s3_key(tag: &str, digest: &str) -> String {
    format!("{S3_DEPLOYMENTS_PREFIX}/{tag}/pyroscope/{digest}")
}

/// Returns the S3 key for monitoring config by digest (deduplicated within deployment)
#[ready(0)]
pub fn monitoring_s3_key(tag: &str, digest: &str) -> String {
    format!("{S3_DEPLOYMENTS_PREFIX}/{tag}/monitoring/{digest}")
}

/// Returns the download URL for Prometheus from GitHub
pub(crate) fn prometheus_download_url(version: &str, architecture: Architecture) -> String {
    format!(
        "https://github.com/prometheus/prometheus/releases/download/v{version}/prometheus-{version}.linux-{arch}.tar.gz",
        arch = architecture.as_str()
    )
}

/// Returns the download URL for Grafana
pub(crate) fn grafana_download_url(version: &str, architecture: Architecture) -> String {
    format!(
        "https://dl.grafana.com/oss/release/grafana_{version}_{arch}.deb",
        arch = architecture.as_str()
    )
}

/// Returns the download URL for Loki from GitHub
pub(crate) fn loki_download_url(version: &str, architecture: Architecture) -> String {
    format!(
        "https://github.com/grafana/loki/releases/download/v{version}/loki-linux-{arch}.zip",
        arch = architecture.as_str()
    )
}

/// Returns the download URL for Pyroscope from GitHub
pub(crate) fn pyroscope_download_url(version: &str, architecture: Architecture) -> String {
    format!(
        "https://github.com/grafana/pyroscope/releases/download/v{version}/pyroscope_{version}_linux_{arch}.tar.gz",
        arch = architecture.as_str()
    )
}

/// Returns the download URL for Tempo from GitHub
pub(crate) fn tempo_download_url(version: &str, architecture: Architecture) -> String {
    format!(
        "https://github.com/grafana/tempo/releases/download/v{version}/tempo_{version}_linux_{arch}.tar.gz",
        arch = architecture.as_str()
    )
}

/// Returns the download URL for Node Exporter from GitHub
pub(crate) fn node_exporter_download_url(version: &str, architecture: Architecture) -> String {
    format!(
        "https://github.com/prometheus/node_exporter/releases/download/v{version}/node_exporter-{version}.linux-{arch}.tar.gz",
        arch = architecture.as_str()
    )
}

/// Returns the download URL for Promtail from GitHub
pub(crate) fn promtail_download_url(version: &str, architecture: Architecture) -> String {
    format!(
        "https://github.com/grafana/loki/releases/download/v{version}/promtail-linux-{arch}.zip",
        arch = architecture.as_str()
    )
}

/// YAML configuration for Grafana datasources (Prometheus, Loki, Tempo, and Pyroscope)
pub const DATASOURCES_YML: &str = r#"
apiVersion: 1
datasources:
  - name: Prometheus
    type: prometheus
    url: http://localhost:9090
    access: proxy
    isDefault: true
  - name: Loki
    type: loki
    url: http://localhost:3100
    access: proxy
    isDefault: false
  - name: Tempo
    type: tempo
    url: http://localhost:3200
    access: proxy
    isDefault: false
  - name: Pyroscope
    type: grafana-pyroscope-datasource
    url: http://localhost:4040
    access: proxy
    isDefault: false
"#;

/// YAML configuration for Grafana dashboard providers
pub const ALL_YML: &str = r#"
apiVersion: 1
providers:
  - name: 'default'
    orgId: 1
    folder: ''
    type: file
    options:
      path: /var/lib/grafana/dashboards
"#;

/// Systemd service file content for Prometheus
pub const PROMETHEUS_SERVICE: &str = r#"[Unit]
Description=Prometheus Monitoring Service
After=network.target

[Service]
ExecStart=/opt/prometheus/prometheus --config.file=/opt/prometheus/prometheus.yml --storage.tsdb.path=/opt/prometheus/data
TimeoutStopSec=60
Restart=always
User=ubuntu
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
"#;

/// Systemd service file content for Promtail
pub const PROMTAIL_SERVICE: &str = r#"[Unit]
Description=Promtail Log Forwarder
After=network.target

[Service]
ExecStart=/opt/promtail/promtail -config.file=/etc/promtail/promtail.yml
TimeoutStopSec=60
Restart=always
User=ubuntu
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
"#;

/// Systemd service file content for Loki
pub const LOKI_SERVICE: &str = r#"[Unit]
Description=Loki Log Aggregation Service
After=network.target

[Service]
ExecStart=/opt/loki/loki -config.file=/etc/loki/loki.yml
TimeoutStopSec=60
Restart=always
User=ubuntu
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
"#;

/// YAML configuration for Loki
pub const LOKI_CONFIG: &str = r#"
auth_enabled: false
target: all
server:
  http_listen_port: 3100
  grpc_listen_port: 9095
common:
  ring:
    kvstore:
      store: inmemory
  replication_factor: 1
  instance_addr: 127.0.0.1
schema_config:
  configs:
    - from: 2020-10-24
      store: tsdb
      object_store: filesystem
      schema: v13
      index:
        prefix: index_
        period: 24h
storage_config:
  tsdb_shipper:
    active_index_directory: /loki/index
    cache_location: /loki/index_cache
  filesystem:
    directory: /loki/chunks
table_manager:
  retention_deletes_enabled: true
  retention_period: 12h
compactor:
  working_directory: /loki/compactor
ingester:
  wal:
    dir: /loki/wal
"#;

/// YAML configuration for Pyroscope
pub const PYROSCOPE_CONFIG: &str = r#"
target: all
server:
  http_listen_port: 4040
  grpc_listen_port: 0
pyroscopedb:
  data_path: /var/lib/pyroscope
self_profiling:
  disable_push: true
"#;

/// Systemd service file content for Pyroscope
pub const PYROSCOPE_SERVICE: &str = r#"[Unit]
Description=Pyroscope Profiling Service
After=network.target

[Service]
ExecStart=/opt/pyroscope/pyroscope --config.file=/etc/pyroscope/pyroscope.yml
TimeoutStopSec=60
Restart=always
User=ubuntu
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
"#;

/// Systemd service file content for Tempo
pub const TEMPO_SERVICE: &str = r#"[Unit]
Description=Tempo Tracing Service
After=network.target
[Service]
ExecStart=/opt/tempo/tempo -config.file=/etc/tempo/tempo.yml
TimeoutStopSec=60
Restart=always
User=ubuntu
LimitNOFILE=infinity
[Install]
WantedBy=multi-user.target
"#;

/// YAML configuration for Tempo
pub const TEMPO_CONFIG: &str = r#"
server:
  grpc_listen_port: 9096
  http_listen_port: 3200
distributor:
  receivers:
    otlp:
      protocols:
        http:
          endpoint: "0.0.0.0:4318"
storage:
  trace:
    backend: local
    local:
      path: /tempo/traces
    wal:
      path: /tempo/wal
ingester:
  max_block_duration: 1h
compactor:
  compaction:
    block_retention: 1h
    compaction_cycle: 1h
"#;

/// URLs for monitoring service installation
#[ready(0)]
pub struct MonitoringUrls {
    pub prometheus_bin: String,
    pub grafana_bin: String,
    pub loki_bin: String,
    pub pyroscope_bin: String,
    pub tempo_bin: String,
    pub node_exporter_bin: String,
    pub prometheus_config: String,
    pub datasources_yml: String,
    pub all_yml: String,
    pub dashboard: String,
    pub loki_yml: String,
    pub pyroscope_yml: String,
    pub tempo_yml: String,
    pub prometheus_service: String,
    pub loki_service: String,
    pub pyroscope_service: String,
    pub tempo_service: String,
    pub node_exporter_service: String,
}

/// Command to install monitoring services (Prometheus, Loki, Grafana, Pyroscope, Tempo) on the monitoring instance
pub(crate) fn install_monitoring_cmd(
    urls: &MonitoringUrls,
    prometheus_version: &str,
    architecture: Architecture,
) -> String {
    let arch = architecture.as_str();
    format!(
        r#"
sudo apt-get update -y
sudo apt-get install -y unzip adduser libfontconfig1 wget tar

# Download all files from S3 concurrently via pre-signed URLs
wget -q --tries=10 --retry-connrefused --waitretry=5 -O /home/ubuntu/prometheus.tar.gz '{}' &
wget -q --tries=10 --retry-connrefused --waitretry=5 -O /home/ubuntu/grafana.deb '{}' &
wget -q --tries=10 --retry-connrefused --waitretry=5 -O /home/ubuntu/loki.zip '{}' &
wget -q --tries=10 --retry-connrefused --waitretry=5 -O /home/ubuntu/pyroscope.tar.gz '{}' &
wget -q --tries=10 --retry-connrefused --waitretry=5 -O /home/ubuntu/tempo.tar.gz '{}' &
wget -q --tries=10 --retry-connrefused --waitretry=5 -O /home/ubuntu/node_exporter.tar.gz '{}' &
wget -q --tries=10 --retry-connrefused --waitretry=5 -O /home/ubuntu/prometheus.yml '{}' &
wget -q --tries=10 --retry-connrefused --waitretry=5 -O /home/ubuntu/datasources.yml '{}' &
wget -q --tries=10 --retry-connrefused --waitretry=5 -O /home/ubuntu/all.yml '{}' &
wget -q --tries=10 --retry-connrefused --waitretry=5 -O /home/ubuntu/dashboard.json '{}' &
wget -q --tries=10 --retry-connrefused --waitretry=5 -O /home/ubuntu/loki.yml '{}' &
wget -q --tries=10 --retry-connrefused --waitretry=5 -O /home/ubuntu/pyroscope.yml '{}' &
wget -q --tries=10 --retry-connrefused --waitretry=5 -O /home/ubuntu/tempo.yml '{}' &
wget -q --tries=10 --retry-connrefused --waitretry=5 -O /home/ubuntu/prometheus.service '{}' &
wget -q --tries=10 --retry-connrefused --waitretry=5 -O /home/ubuntu/loki.service '{}' &
wget -q --tries=10 --retry-connrefused --waitretry=5 -O /home/ubuntu/pyroscope.service '{}' &
wget -q --tries=10 --retry-connrefused --waitretry=5 -O /home/ubuntu/tempo.service '{}' &
wget -q --tries=10 --retry-connrefused --waitretry=5 -O /home/ubuntu/node_exporter.service '{}' &
wait

# Verify all downloads succeeded
for f in prometheus.tar.gz grafana.deb loki.zip pyroscope.tar.gz tempo.tar.gz node_exporter.tar.gz \
         prometheus.yml datasources.yml all.yml dashboard.json loki.yml pyroscope.yml tempo.yml \
         prometheus.service loki.service pyroscope.service tempo.service node_exporter.service; do
    if [ ! -f "/home/ubuntu/$f" ]; then
        echo "ERROR: Failed to download $f" >&2
        exit 1
    fi
done

# Install Prometheus
sudo mkdir -p /opt/prometheus /opt/prometheus/data
sudo chown -R ubuntu:ubuntu /opt/prometheus
tar xvfz /home/ubuntu/prometheus.tar.gz -C /home/ubuntu
sudo mv /home/ubuntu/prometheus-{prometheus_version}.linux-{arch} /opt/prometheus/prometheus-{prometheus_version}.linux-{arch}
sudo ln -s /opt/prometheus/prometheus-{prometheus_version}.linux-{arch}/prometheus /opt/prometheus/prometheus
sudo chmod +x /opt/prometheus/prometheus

# Install Grafana
sudo dpkg -i /home/ubuntu/grafana.deb
sudo apt-get install -f -y

# Install Loki
sudo mkdir -p /opt/loki /loki/index /loki/index_cache /loki/chunks /loki/compactor /loki/wal
sudo chown -R ubuntu:ubuntu /opt/loki /loki
unzip -o /home/ubuntu/loki.zip -d /home/ubuntu
sudo mv /home/ubuntu/loki-linux-{arch} /opt/loki/loki
sudo chmod +x /opt/loki/loki

# Install Pyroscope
sudo mkdir -p /opt/pyroscope /var/lib/pyroscope
sudo chown -R ubuntu:ubuntu /opt/pyroscope /var/lib/pyroscope
tar xvfz /home/ubuntu/pyroscope.tar.gz -C /home/ubuntu
sudo mv /home/ubuntu/pyroscope /opt/pyroscope/pyroscope
sudo chmod +x /opt/pyroscope/pyroscope

# Install Tempo
sudo mkdir -p /opt/tempo /tempo/traces /tempo/wal
sudo chown -R ubuntu:ubuntu /opt/tempo /tempo
tar xvfz /home/ubuntu/tempo.tar.gz -C /home/ubuntu
sudo mv /home/ubuntu/tempo /opt/tempo/tempo
sudo chmod +x /opt/tempo/tempo

# Install Node Exporter
sudo mkdir -p /opt/node_exporter
sudo chown -R ubuntu:ubuntu /opt/node_exporter
tar xvfz /home/ubuntu/node_exporter.tar.gz -C /home/ubuntu
sudo mv /home/ubuntu/node_exporter-*.linux-{arch} /opt/node_exporter/
sudo ln -s /opt/node_exporter/node_exporter-*.linux-{arch}/node_exporter /opt/node_exporter/node_exporter
sudo chmod +x /opt/node_exporter/node_exporter

# Configure Grafana
sudo sed -i '/^\[auth.anonymous\]$/,/^\[/ {{ /^; *enabled = /s/.*/enabled = true/; /^; *org_role = /s/.*/org_role = Admin/ }}' /etc/grafana/grafana.ini
sudo mkdir -p /etc/grafana/provisioning/datasources /etc/grafana/provisioning/dashboards /var/lib/grafana/dashboards

# Install Pyroscope data source plugin
sudo grafana-cli plugins install grafana-pyroscope-datasource

# Install configuration files
sudo mv /home/ubuntu/prometheus.yml /opt/prometheus/prometheus.yml
sudo mv /home/ubuntu/datasources.yml /etc/grafana/provisioning/datasources/datasources.yml
sudo mv /home/ubuntu/all.yml /etc/grafana/provisioning/dashboards/all.yml
sudo mv /home/ubuntu/dashboard.json /var/lib/grafana/dashboards/dashboard.json
sudo mkdir -p /etc/loki
sudo mv /home/ubuntu/loki.yml /etc/loki/loki.yml
sudo chown root:root /etc/loki/loki.yml
sudo mkdir -p /etc/pyroscope
sudo mv /home/ubuntu/pyroscope.yml /etc/pyroscope/pyroscope.yml
sudo chown root:root /etc/pyroscope/pyroscope.yml
sudo mkdir -p /etc/tempo
sudo mv /home/ubuntu/tempo.yml /etc/tempo/tempo.yml
sudo chown root:root /etc/tempo/tempo.yml

# Install service files
sudo mv /home/ubuntu/prometheus.service /etc/systemd/system/prometheus.service
sudo mv /home/ubuntu/loki.service /etc/systemd/system/loki.service
sudo mv /home/ubuntu/pyroscope.service /etc/systemd/system/pyroscope.service
sudo mv /home/ubuntu/tempo.service /etc/systemd/system/tempo.service
sudo mv /home/ubuntu/node_exporter.service /etc/systemd/system/node_exporter.service
"#,
        urls.prometheus_bin,
        urls.grafana_bin,
        urls.loki_bin,
        urls.pyroscope_bin,
        urls.tempo_bin,
        urls.node_exporter_bin,
        urls.prometheus_config,
        urls.datasources_yml,
        urls.all_yml,
        urls.dashboard,
        urls.loki_yml,
        urls.pyroscope_yml,
        urls.tempo_yml,
        urls.prometheus_service,
        urls.loki_service,
        urls.pyroscope_service,
        urls.tempo_service,
        urls.node_exporter_service,
    )
}

/// Continuation of monitoring install command (services startup)
#[ready(0)]
pub const fn start_monitoring_services_cmd() -> &'static str {
    r#"
sudo chown -R grafana:grafana /etc/grafana /var/lib/grafana

# Start services
sudo systemctl daemon-reload
sudo systemctl start node_exporter
sudo systemctl enable node_exporter
sudo systemctl start prometheus
sudo systemctl enable prometheus
sudo systemctl start loki
sudo systemctl enable loki
sudo systemctl start pyroscope
sudo systemctl enable pyroscope
sudo systemctl start tempo
sudo systemctl enable tempo
sudo systemctl restart grafana-server
sudo systemctl enable grafana-server
"#
}

/// URLs for binary instance installation
#[ready(0)]
pub struct InstanceUrls {
    pub binary: String,
    pub config: String,
    pub hosts: String,
    pub promtail_bin: String,
    pub promtail_config: String,
    pub promtail_service: String,
    pub node_exporter_bin: String,
    pub node_exporter_service: String,
    pub binary_service: String,
    pub logrotate_conf: String,
    pub pyroscope_script: String,
    pub pyroscope_service: String,
    pub pyroscope_timer: String,
}

/// Command to install all services on binary instances
pub(crate) fn install_binary_cmd(
    urls: &InstanceUrls,
    profiling: bool,
    architecture: Architecture,
) -> String {
    let arch = architecture.as_str();
    let mut script = format!(
        r#"
# Install base tools and dependencies
sudo apt-get update -y
sudo apt-get install -y logrotate jq wget unzip libjemalloc2 linux-tools-common linux-tools-generic linux-tools-$(uname -r)

# Download all files from S3 concurrently via pre-signed URLs
wget -q --tries=10 --retry-connrefused --waitretry=5 -O /home/ubuntu/binary '{}' &
wget -q --tries=10 --retry-connrefused --waitretry=5 -O /home/ubuntu/config.conf '{}' &
wget -q --tries=10 --retry-connrefused --waitretry=5 -O /home/ubuntu/hosts.yaml '{}' &
wget -q --tries=10 --retry-connrefused --waitretry=5 -O /home/ubuntu/promtail.zip '{}' &
wget -q --tries=10 --retry-connrefused --waitretry=5 -O /home/ubuntu/promtail.yml '{}' &
wget -q --tries=10 --retry-connrefused --waitretry=5 -O /home/ubuntu/promtail.service '{}' &
wget -q --tries=10 --retry-connrefused --waitretry=5 -O /home/ubuntu/node_exporter.tar.gz '{}' &
wget -q --tries=10 --retry-connrefused --waitretry=5 -O /home/ubuntu/node_exporter.service '{}' &
wget -q --tries=10 --retry-connrefused --waitretry=5 -O /home/ubuntu/binary.service '{}' &
wget -q --tries=10 --retry-connrefused --waitretry=5 -O /home/ubuntu/logrotate.conf '{}' &
wget -q --tries=10 --retry-connrefused --waitretry=5 -O /home/ubuntu/pyroscope-agent.sh '{}' &
wget -q --tries=10 --retry-connrefused --waitretry=5 -O /home/ubuntu/pyroscope-agent.service '{}' &
wget -q --tries=10 --retry-connrefused --waitretry=5 -O /home/ubuntu/pyroscope-agent.timer '{}' &
wait

# Verify all downloads succeeded
for f in binary config.conf hosts.yaml promtail.zip promtail.yml promtail.service \
         node_exporter.tar.gz node_exporter.service binary.service logrotate.conf \
         pyroscope-agent.sh pyroscope-agent.service pyroscope-agent.timer; do
    if [ ! -f "/home/ubuntu/$f" ]; then
        echo "ERROR: Failed to download $f" >&2
        exit 1
    fi
done

# Install Promtail
sudo mkdir -p /opt/promtail /etc/promtail
sudo chown -R ubuntu:ubuntu /opt/promtail
unzip -o /home/ubuntu/promtail.zip -d /home/ubuntu
sudo mv /home/ubuntu/promtail-linux-{arch} /opt/promtail/promtail
sudo chmod +x /opt/promtail/promtail
sudo mv /home/ubuntu/promtail.yml /etc/promtail/promtail.yml
sudo mv /home/ubuntu/promtail.service /etc/systemd/system/promtail.service
sudo chown root:root /etc/promtail/promtail.yml

# Install Node Exporter
sudo mkdir -p /opt/node_exporter
sudo chown -R ubuntu:ubuntu /opt/node_exporter
tar xvfz /home/ubuntu/node_exporter.tar.gz -C /home/ubuntu
sudo mv /home/ubuntu/node_exporter-*.linux-{arch} /opt/node_exporter/
sudo ln -s /opt/node_exporter/node_exporter-*.linux-{arch}/node_exporter /opt/node_exporter/node_exporter
sudo chmod +x /opt/node_exporter/node_exporter
sudo mv /home/ubuntu/node_exporter.service /etc/systemd/system/node_exporter.service

# Setup binary
chmod +x /home/ubuntu/binary
sudo touch /var/log/binary.log && sudo chown ubuntu:ubuntu /var/log/binary.log
sudo mv /home/ubuntu/binary.service /etc/systemd/system/binary.service

# Setup logrotate
sudo mv /home/ubuntu/logrotate.conf /etc/logrotate.d/binary
sudo chown root:root /etc/logrotate.d/binary
echo "0 * * * * /usr/sbin/logrotate /etc/logrotate.d/binary" | crontab -

# Setup pyroscope agent
sudo ln -s "$(find /usr/lib/linux-tools/*/perf | head -1)" /usr/local/bin/perf
sudo chmod +x /home/ubuntu/pyroscope-agent.sh
sudo mv /home/ubuntu/pyroscope-agent.service /etc/systemd/system/pyroscope-agent.service
sudo mv /home/ubuntu/pyroscope-agent.timer /etc/systemd/system/pyroscope-agent.timer

# Start services
sudo systemctl daemon-reload
sudo systemctl enable --now promtail
sudo systemctl enable --now node_exporter
sudo systemctl enable --now binary
"#,
        urls.binary,
        urls.config,
        urls.hosts,
        urls.promtail_bin,
        urls.promtail_config,
        urls.promtail_service,
        urls.node_exporter_bin,
        urls.node_exporter_service,
        urls.binary_service,
        urls.logrotate_conf,
        urls.pyroscope_script,
        urls.pyroscope_service,
        urls.pyroscope_timer,
    );
    if profiling {
        script.push_str(
            r#"
sudo systemctl enable --now pyroscope-agent.timer
"#,
        );
    }
    script
}

/// Generates Promtail configuration with the monitoring instance's private IP and instance name
#[ready(0)]
pub fn promtail_config(
    monitoring_private_ip: &str,
    instance_name: &str,
    ip: &str,
    region: &str,
    arch: &str,
) -> String {
    format!(
        r#"
server:
  http_listen_port: 9080
  grpc_listen_port: 0
positions:
  filename: /tmp/positions.yaml
clients:
  - url: http://{monitoring_private_ip}:3100/loki/api/v1/push
scrape_configs:
  - job_name: binary_logs
    static_configs:
      - targets:
          - localhost
        labels:
          deployer_name: {instance_name}
          deployer_ip: {ip}
          deployer_region: {region}
          deployer_arch: {arch}
          __path__: /var/log/binary.log
"#
    )
}

/// Systemd service file content for Node Exporter
pub const NODE_EXPORTER_SERVICE: &str = r#"[Unit]
Description=Node Exporter
After=network.target

[Service]
ExecStart=/opt/node_exporter/node_exporter
TimeoutStopSec=60
Restart=always
User=ubuntu
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
"#;

/// Generates Prometheus configuration with scrape targets for all instance IPs
#[ready(0)]
pub fn generate_prometheus_config(instances: &[(&str, &str, &str, &str)]) -> String {
    let mut config = String::from(
        r#"
global:
  scrape_interval: 15s
scrape_configs:
  - job_name: 'monitoring_system'
    static_configs:
      - targets: ['localhost:9100']
"#,
    );
    for (name, ip, region, arch) in instances {
        config.push_str(&format!(
            r#"
  - job_name: '{name}_binary'
    static_configs:
      - targets: ['{ip}:9090']
        labels:
          deployer_name: '{name}'
          deployer_ip: '{ip}'
          deployer_region: '{region}'
          deployer_arch: '{arch}'
  - job_name: '{name}_system'
    static_configs:
      - targets: ['{ip}:9100']
        labels:
          deployer_name: '{name}'
          deployer_ip: '{ip}'
          deployer_region: '{region}'
          deployer_arch: '{arch}'
"#
        ));
    }
    config
}

/// Logrotate configuration for binary logs
pub const LOGROTATE_CONF: &str = r#"
/var/log/binary.log {
    rotate 0
    copytruncate
    missingok
    notifempty
}
"#;

/// Configuration for BBR sysctl settings
pub const BBR_CONF: &str = "net.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr\n";

/// Generates systemd service file content for the deployed binary
pub(crate) fn binary_service(architecture: Architecture) -> String {
    let lib_arch = architecture.linux_lib();
    format!(
        r#"[Unit]
Description=Deployed Binary Service
After=network.target

[Service]
Environment="LD_PRELOAD=/usr/lib/{lib_arch}/libjemalloc.so.2"
ExecStart=/home/ubuntu/binary --hosts=/home/ubuntu/hosts.yaml --config=/home/ubuntu/config.conf
TimeoutStopSec=60
Restart=always
User=ubuntu
LimitNOFILE=infinity
StandardOutput=append:/var/log/binary.log
StandardError=append:/var/log/binary.log

[Install]
WantedBy=multi-user.target
"#
    )
}

/// Shell script content for the Pyroscope agent (perf + wget)
#[ready(0)]
pub fn generate_pyroscope_script(
    monitoring_private_ip: &str,
    name: &str,
    ip: &str,
    region: &str,
    arch: &str,
) -> String {
    format!(
        r#"#!/bin/bash
set -e

SERVICE_NAME="binary.service"
PERF_DATA_FILE="/tmp/perf.data"
PERF_STACK_FILE="/tmp/perf.stack"
PROFILE_DURATION=60 # seconds
PERF_FREQ=100 # Hz

# Construct the Pyroscope application name with tags
RAW_APP_NAME="binary{{deployer_name={name},deployer_ip={ip},deployer_region={region},deployer_arch={arch}}}"
APP_NAME=$(jq -nr --arg str "$RAW_APP_NAME" '$str | @uri')

# Get the PID of the binary service
PID=$(systemctl show --property MainPID ${{SERVICE_NAME}} | cut -d= -f2)
if [ -z "$PID" ] || [ "$PID" -eq 0 ]; then
  echo "Error: Could not get PID for ${{SERVICE_NAME}}." >&2
  exit 1
fi

# Record performance data
echo "Recording perf data for PID ${{PID}}..."
sudo perf record -F ${{PERF_FREQ}} -p ${{PID}} -o ${{PERF_DATA_FILE}} -g --call-graph fp -- sleep ${{PROFILE_DURATION}}

# Generate folded stack report
echo "Generating folded stack report..."
sudo perf report -i ${{PERF_DATA_FILE}} --stdio --no-children -g folded,0,caller,count -s comm | \
    awk '/^[0-9]+\.[0-9]+%/ {{ comm = $2 }} /^[0-9]/ {{ print comm ";" substr($0, index($0, $2)), $1 }}' > ${{PERF_STACK_FILE}}

# Check if stack file is empty (perf might fail silently sometimes)
if [ ! -s "${{PERF_STACK_FILE}}" ]; then
    echo "Warning: ${{PERF_STACK_FILE}} is empty. Skipping upload." >&2
    # Clean up empty perf.data
    sudo rm -f ${{PERF_DATA_FILE}} ${{PERF_STACK_FILE}}
    exit 0
fi

# Calculate timestamps
UNTIL_TS=$(date +%s)
FROM_TS=$((UNTIL_TS - PROFILE_DURATION))

# Upload to Pyroscope
echo "Uploading profile to Pyroscope at {monitoring_private_ip}..."
wget --post-file="${{PERF_STACK_FILE}}" \
    --header="Content-Type: text/plain" \
    --quiet \
    -O /dev/null \
    "http://{monitoring_private_ip}:4040/ingest?name=${{APP_NAME}}&format=folded&units=samples&aggregationType=sum&sampleType=cpu&from=${{FROM_TS}}&until=${{UNTIL_TS}}&spyName=perf"

echo "Profile upload complete."
sudo rm -f ${{PERF_DATA_FILE}} ${{PERF_STACK_FILE}}
"#
    )
}

/// Systemd service file content for the Pyroscope agent script
pub const PYROSCOPE_AGENT_SERVICE: &str = r#"[Unit]
Description=Pyroscope Agent (Perf Script Runner)
Wants=network-online.target
After=network-online.target binary.service

[Service]
Type=oneshot
User=ubuntu
ExecStart=/home/ubuntu/pyroscope-agent.sh

[Install]
WantedBy=multi-user.target
"#;

/// Systemd timer file content for the Pyroscope agent service
pub const PYROSCOPE_AGENT_TIMER: &str = r#"[Unit]
Description=Run Pyroscope Agent periodically

[Timer]
# Wait a bit after boot before the first run
OnBootSec=2min
# Run roughly every minute after the last run finished
OnUnitInactiveSec=1min
Unit=pyroscope-agent.service
# Randomize the delay to avoid thundering herd
RandomizedDelaySec=10s

[Install]
WantedBy=timers.target
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_binary_s3_keys_arm64() {
        let arch = Architecture::Arm64;
        assert_eq!(
            prometheus_bin_s3_key("3.2.0", arch),
            "tools/binaries/prometheus/3.2.0/linux-arm64/prometheus-3.2.0.linux-arm64.tar.gz"
        );
        assert_eq!(
            grafana_bin_s3_key("11.5.2", arch),
            "tools/binaries/grafana/11.5.2/linux-arm64/grafana_11.5.2_arm64.deb"
        );
        assert_eq!(
            loki_bin_s3_key("3.4.2", arch),
            "tools/binaries/loki/3.4.2/linux-arm64/loki-linux-arm64.zip"
        );
        assert_eq!(
            pyroscope_bin_s3_key("1.12.0", arch),
            "tools/binaries/pyroscope/1.12.0/linux-arm64/pyroscope_1.12.0_linux_arm64.tar.gz"
        );
        assert_eq!(
            tempo_bin_s3_key("2.7.1", arch),
            "tools/binaries/tempo/2.7.1/linux-arm64/tempo_2.7.1_linux_arm64.tar.gz"
        );
        assert_eq!(
            node_exporter_bin_s3_key("1.9.0", arch),
            "tools/binaries/node-exporter/1.9.0/linux-arm64/node_exporter-1.9.0.linux-arm64.tar.gz"
        );
        assert_eq!(
            promtail_bin_s3_key("3.4.2", arch),
            "tools/binaries/promtail/3.4.2/linux-arm64/promtail-linux-arm64.zip"
        );
    }

    #[test]
    fn test_binary_s3_keys_x86_64() {
        let arch = Architecture::X86_64;
        assert_eq!(
            prometheus_bin_s3_key("3.2.0", arch),
            "tools/binaries/prometheus/3.2.0/linux-amd64/prometheus-3.2.0.linux-amd64.tar.gz"
        );
        assert_eq!(
            grafana_bin_s3_key("11.5.2", arch),
            "tools/binaries/grafana/11.5.2/linux-amd64/grafana_11.5.2_amd64.deb"
        );
        assert_eq!(
            loki_bin_s3_key("3.4.2", arch),
            "tools/binaries/loki/3.4.2/linux-amd64/loki-linux-amd64.zip"
        );
        assert_eq!(
            pyroscope_bin_s3_key("1.12.0", arch),
            "tools/binaries/pyroscope/1.12.0/linux-amd64/pyroscope_1.12.0_linux_amd64.tar.gz"
        );
        assert_eq!(
            tempo_bin_s3_key("2.7.1", arch),
            "tools/binaries/tempo/2.7.1/linux-amd64/tempo_2.7.1_linux_amd64.tar.gz"
        );
        assert_eq!(
            node_exporter_bin_s3_key("1.9.0", arch),
            "tools/binaries/node-exporter/1.9.0/linux-amd64/node_exporter-1.9.0.linux-amd64.tar.gz"
        );
        assert_eq!(
            promtail_bin_s3_key("3.4.2", arch),
            "tools/binaries/promtail/3.4.2/linux-amd64/promtail-linux-amd64.zip"
        );
    }

    #[test]
    fn test_config_s3_keys() {
        let version = DEPLOYER_VERSION;

        assert_eq!(
            prometheus_service_s3_key(),
            format!("tools/configs/{version}/prometheus/service")
        );
        assert_eq!(
            grafana_datasources_s3_key(),
            format!("tools/configs/{version}/grafana/datasources.yml")
        );
        assert_eq!(
            grafana_dashboards_s3_key(),
            format!("tools/configs/{version}/grafana/all.yml")
        );
        assert_eq!(
            loki_config_s3_key(),
            format!("tools/configs/{version}/loki/config.yml")
        );
        assert_eq!(
            loki_service_s3_key(),
            format!("tools/configs/{version}/loki/service")
        );
        assert_eq!(
            pyroscope_config_s3_key(),
            format!("tools/configs/{version}/pyroscope/config.yml")
        );
        assert_eq!(
            pyroscope_service_s3_key(),
            format!("tools/configs/{version}/pyroscope/service")
        );
        assert_eq!(
            tempo_config_s3_key(),
            format!("tools/configs/{version}/tempo/config.yml")
        );
        assert_eq!(
            tempo_service_s3_key(),
            format!("tools/configs/{version}/tempo/service")
        );
        assert_eq!(
            node_exporter_service_s3_key(),
            format!("tools/configs/{version}/node-exporter/service")
        );
        assert_eq!(
            promtail_service_s3_key(),
            format!("tools/configs/{version}/promtail/service")
        );
        assert_eq!(
            pyroscope_agent_service_s3_key(),
            format!("tools/configs/{version}/pyroscope/agent.service")
        );
        assert_eq!(
            pyroscope_agent_timer_s3_key(),
            format!("tools/configs/{version}/pyroscope/agent.timer")
        );
        assert_eq!(
            bbr_config_s3_key(),
            format!("tools/configs/{version}/system/bbr.conf")
        );
        assert_eq!(
            logrotate_config_s3_key(),
            format!("tools/configs/{version}/system/logrotate.conf")
        );
        assert_eq!(
            binary_service_s3_key_for_arch(Architecture::Arm64),
            format!("tools/configs/{version}/binary/service-arm64")
        );
        assert_eq!(
            binary_service_s3_key_for_arch(Architecture::X86_64),
            format!("tools/configs/{version}/binary/service-amd64")
        );
    }

    #[test]
    fn test_deployment_s3_keys() {
        let digest = "abc123def456";
        assert_eq!(
            binary_s3_key("my-tag", digest),
            "deployments/my-tag/binaries/abc123def456"
        );
        assert_eq!(
            config_s3_key("my-tag", digest),
            "deployments/my-tag/configs/abc123def456"
        );
        assert_eq!(
            hosts_s3_key("my-tag", digest),
            "deployments/my-tag/hosts/abc123def456"
        );
        assert_eq!(
            promtail_s3_key("my-tag", digest),
            "deployments/my-tag/promtail/abc123def456"
        );
        assert_eq!(
            pyroscope_s3_key("my-tag", digest),
            "deployments/my-tag/pyroscope/abc123def456"
        );
        assert_eq!(
            monitoring_s3_key("my-tag", digest),
            "deployments/my-tag/monitoring/abc123def456"
        );
    }
}
