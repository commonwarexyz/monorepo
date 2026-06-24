//! Service configuration for Prometheus, Loki, Grafana, Promtail, tracer, and a caller-provided binary

use crate::aws::{
    s3::{DEPLOYMENTS_PREFIX, TOOLS_BINARIES_PREFIX, TOOLS_CONFIGS_PREFIX, WGET},
    Architecture,
};

// Binary artifacts and user SSH state live under this directory. NVMe-backed instances mount
// instance-store storage here so existing binary configs use NVMe without extra configuration.
const HOME_DIRECTORY: &str = "/home/ubuntu";

// Install path for the Docker static binary.
const DOCKER_BIN: &str = "/usr/local/bin/docker";

/// Deployer version used to namespace static configs in S3
const DEPLOYER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Version of the Grafana Node Exporter Full dashboard to provision.
///
/// The public dashboard is available at:
/// <https://grafana.com/grafana/dashboards/1860-node-exporter-full/>
pub const GRAFANA_NODE_EXPORTER_DASHBOARD_VERSION: &str = "45";

/// Version of Docker static binaries to download and install
pub const DOCKER_VERSION: &str = "29.6.0";

/// Version of Samply to download and install
pub const SAMPLY_VERSION: &str = "0.13.1";

/// Version of libjemalloc2 package for Ubuntu 24.04
pub const LIBJEMALLOC2_VERSION: &str = "5.3.0-2build1";

/// Version of logrotate package for Ubuntu 24.04
pub const LOGROTATE_VERSION: &str = "3.21.0-2build1";

/// Ubuntu package archive base URL for arm64
const UBUNTU_ARCHIVE_ARM64: &str = "http://ports.ubuntu.com/ubuntu-ports/pool";

/// Ubuntu package archive base URL for x86_64
const UBUNTU_ARCHIVE_X86_64: &str = "http://archive.ubuntu.com/ubuntu/pool";

/// Image for Prometheus metrics storage and querying
pub const PROMETHEUS_IMAGE: &str = "prom/prometheus:v3.2.0";

/// Image for Promtail log forwarding
pub const PROMTAIL_IMAGE: &str = "grafana/promtail:3.4.2";

/// Image for Node Exporter system metrics
pub const NODE_EXPORTER_IMAGE: &str = "prom/node-exporter:v1.9.0";

/// Image for Loki log storage and querying
pub const LOKI_IMAGE: &str = "grafana/loki:3.4.2";

/// Image for Tempo trace storage and querying
pub const TEMPO_IMAGE: &str = "grafana/tempo:2.7.1";

/// Image for Pyroscope profile storage and querying
pub const PYROSCOPE_IMAGE: &str = "grafana/pyroscope:1.12.0";

/// Image for Grafana dashboards
pub const GRAFANA_IMAGE: &str = "grafana/grafana:11.5.2";

/// Image for Tracer trace viewing
pub const TRACER_IMAGE: &str = "ghcr.io/clabby/tracer-web:0.1.1";

#[derive(Clone, Copy)]
struct ImageService {
    service: &'static str,
    description: &'static str,
    image: &'static str,
    network_host: bool,
    pid_host: bool,
    user: Option<&'static str>,
    env: &'static [(&'static str, &'static str)],
    volumes: &'static [&'static str],
    args: &'static [&'static str],
    options: &'static [&'static str],
    after: &'static [&'static str],
}

const NODE_EXPORTER_ARGS: &[&str] = &[
    "--path.procfs=/host/proc",
    "--path.sysfs=/host/sys",
    "--path.rootfs=/host/rootfs",
    "--collector.filesystem.mount-points-exclude=^/(dev|proc|sys|var/lib/docker/.+|var/lib/containers/.+)($|/)",
];

const NODE_EXPORTER_VOLUMES: &[&str] = &[
    "/proc:/host/proc:ro",
    "/sys:/host/sys:ro",
    "/:/host/rootfs:ro,rslave",
];

const PROMTAIL_VOLUMES: &[&str] = &[
    "/etc/promtail:/etc/promtail:ro",
    "/var/log:/var/log:ro",
    "/var/lib/promtail:/var/lib/promtail",
];

const MONITORING_IMAGE_SERVICES: &[ImageService] = &[
    ImageService {
        service: "node_exporter",
        description: "Node Exporter",
        image: NODE_EXPORTER_IMAGE,
        network_host: true,
        pid_host: true,
        user: Some("0:0"),
        env: &[],
        volumes: NODE_EXPORTER_VOLUMES,
        args: NODE_EXPORTER_ARGS,
        options: &[],
        after: &[],
    },
    ImageService {
        service: "prometheus",
        description: "Prometheus Monitoring Service",
        image: PROMETHEUS_IMAGE,
        network_host: true,
        pid_host: false,
        user: Some("0:0"),
        env: &[],
        volumes: &[
            "/opt/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml:ro",
            "/opt/prometheus/data:/prometheus",
        ],
        args: &[
            "--config.file=/etc/prometheus/prometheus.yml",
            "--storage.tsdb.path=/prometheus",
        ],
        options: &[],
        after: &["node_exporter.service"],
    },
    ImageService {
        service: "loki",
        description: "Loki Log Aggregation Service",
        image: LOKI_IMAGE,
        network_host: true,
        pid_host: false,
        user: Some("0:0"),
        env: &[],
        volumes: &["/etc/loki/loki.yml:/etc/loki/loki.yml:ro", "/loki:/loki"],
        args: &["-config.file=/etc/loki/loki.yml"],
        options: &[],
        after: &[],
    },
    ImageService {
        service: "pyroscope",
        description: "Pyroscope Profiling Service",
        image: PYROSCOPE_IMAGE,
        network_host: true,
        pid_host: false,
        user: Some("0:0"),
        env: &[],
        volumes: &[
            "/etc/pyroscope/pyroscope.yml:/etc/pyroscope/pyroscope.yml:ro",
            "/var/lib/pyroscope:/var/lib/pyroscope",
        ],
        args: &["--config.file=/etc/pyroscope/pyroscope.yml"],
        options: &[],
        after: &[],
    },
    ImageService {
        service: "tempo",
        description: "Tempo Tracing Service",
        image: TEMPO_IMAGE,
        network_host: true,
        pid_host: false,
        user: Some("0:0"),
        env: &[],
        volumes: &[
            "/etc/tempo/tempo.yml:/etc/tempo/tempo.yml:ro",
            "/tempo:/var/tempo",
        ],
        args: &["-config.file=/etc/tempo/tempo.yml"],
        options: &[],
        after: &[],
    },
    ImageService {
        service: "grafana",
        description: "Grafana Dashboard Service",
        image: GRAFANA_IMAGE,
        network_host: true,
        pid_host: false,
        user: Some("0:0"),
        env: &[
            ("GF_AUTH_ANONYMOUS_ENABLED", "true"),
            ("GF_AUTH_ANONYMOUS_ORG_ROLE", "Admin"),
            ("GF_INSTALL_PLUGINS", "grafana-pyroscope-app"),
        ],
        volumes: &[
            "/etc/grafana/provisioning:/etc/grafana/provisioning:ro",
            "/var/lib/grafana:/var/lib/grafana",
        ],
        args: &[],
        options: &[],
        after: &[
            "prometheus.service",
            "loki.service",
            "tempo.service",
            "pyroscope.service",
        ],
    },
    ImageService {
        service: "tracer",
        description: "Tracer Trace Viewer",
        image: TRACER_IMAGE,
        network_host: true,
        pid_host: false,
        user: None,
        env: &[("TEMPO_URL", "http://127.0.0.1:3200")],
        volumes: &[],
        args: &[],
        options: &[],
        after: &["tempo.service"],
    },
];

const BINARY_IMAGE_SERVICES: &[ImageService] = &[
    ImageService {
        service: "promtail",
        description: "Promtail Log Forwarder",
        image: PROMTAIL_IMAGE,
        network_host: true,
        pid_host: false,
        user: Some("0:0"),
        env: &[],
        volumes: PROMTAIL_VOLUMES,
        args: &["-config.file=/etc/promtail/promtail.yml"],
        options: &[],
        after: &["binary.service"],
    },
    ImageService {
        service: "node_exporter",
        description: "Node Exporter",
        image: NODE_EXPORTER_IMAGE,
        network_host: true,
        pid_host: true,
        user: Some("0:0"),
        env: &[],
        volumes: NODE_EXPORTER_VOLUMES,
        args: NODE_EXPORTER_ARGS,
        options: &[],
        after: &[],
    },
];

impl ImageService {
    fn service_file(self) -> String {
        let after = self.after.join(" ");
        let mut run_options = String::new();
        if self.network_host {
            run_options.push_str(" --network host");
        }
        if self.pid_host {
            run_options.push_str(" --pid host");
        }
        if let Some(user) = self.user {
            run_options.push_str(" --user ");
            run_options.push_str(user);
        }
        for (key, value) in self.env {
            run_options.push_str(" --env ");
            run_options.push_str(key);
            run_options.push('=');
            run_options.push_str(value);
        }
        for volume in self.volumes {
            run_options.push_str(" --volume ");
            run_options.push_str(volume);
        }
        for option in self.options {
            run_options.push(' ');
            run_options.push_str(option);
        }
        let args = if self.args.is_empty() {
            String::new()
        } else {
            format!(" {}", self.args.join(" "))
        };
        let after_line = if after.is_empty() {
            "After=network-online.target docker.service".to_string()
        } else {
            format!("After=network-online.target docker.service {after}")
        };

        format!(
            r#"[Unit]
Description={description}
Wants=network-online.target
{after_line}
Requires=docker.service

[Service]
ExecStartPre=-{docker_bin} rm -f {service}
ExecStart={docker_bin} run --rm --name {service}{run_options} {image}{args}
TimeoutStopSec=60
Restart=always

[Install]
WantedBy=multi-user.target
"#,
            service = self.service,
            description = self.description,
            docker_bin = DOCKER_BIN,
            image = self.image,
        )
    }
}

/// Maps an upstream image reference to a filesystem- and S3-safe token (e.g. `prom_prometheus_v3.2.0`).
pub(crate) fn sanitize_image(image: &str) -> String {
    image.replace(['/', ':'], "_")
}

/// Returns the on-instance filename for an image tarball (e.g. `prom_prometheus_v3.2.0.tar.gz`).
pub(crate) fn image_file_name(image: &str) -> String {
    format!("{}.tar.gz", sanitize_image(image))
}

/// Returns the S3 key for a cached image tarball (`docker save` output, per architecture).
pub fn image_s3_key(image: &str, architecture: Architecture) -> String {
    format!(
        "{TOOLS_BINARIES_PREFIX}/images/{name}/linux-{arch}/image.tar.gz",
        name = sanitize_image(image),
        arch = architecture.as_str(),
    )
}

/// Returns the distinct images required by the monitoring instance.
pub(crate) fn monitoring_images() -> impl Iterator<Item = &'static str> {
    distinct_images(MONITORING_IMAGE_SERVICES)
}

/// Returns the distinct images required by binary instances.
pub(crate) fn binary_images() -> impl Iterator<Item = &'static str> {
    distinct_images(BINARY_IMAGE_SERVICES)
}

fn distinct_images(services: &'static [ImageService]) -> impl Iterator<Item = &'static str> {
    let mut seen = Vec::new();
    services.iter().filter_map(move |service| {
        if seen.contains(&service.image) {
            None
        } else {
            seen.push(service.image);
            Some(service.image)
        }
    })
}

pub(crate) fn docker_bin_s3_key(version: &str, architecture: Architecture) -> String {
    let arch = docker_static_arch(architecture);
    format!("{TOOLS_BINARIES_PREFIX}/docker/{version}/linux-{arch}/docker-{version}.tgz")
}

pub(crate) fn samply_bin_s3_key(version: &str, architecture: Architecture) -> String {
    let arch = match architecture {
        Architecture::Arm64 => "aarch64",
        Architecture::X86_64 => "x86_64",
    };
    format!("{TOOLS_BINARIES_PREFIX}/samply/{version}/linux-{arch}/samply-{arch}-unknown-linux-gnu.tar.xz")
}

pub(crate) fn libjemalloc_bin_s3_key(version: &str, architecture: Architecture) -> String {
    format!(
        "{TOOLS_BINARIES_PREFIX}/libjemalloc2/{version}/linux-{arch}/libjemalloc2_{version}_{arch}.deb",
        arch = architecture.as_str()
    )
}

pub(crate) fn logrotate_bin_s3_key(version: &str, architecture: Architecture) -> String {
    format!(
        "{TOOLS_BINARIES_PREFIX}/logrotate/{version}/linux-{arch}/logrotate_{version}_{arch}.deb",
        arch = architecture.as_str()
    )
}

// S3 key functions for component configs and services (include deployer version for cache invalidation)
//
// Convention: {TOOLS_CONFIGS_PREFIX}/{deployer_version}/{component}/{file}

pub fn grafana_datasources_s3_key() -> String {
    format!("{TOOLS_CONFIGS_PREFIX}/{DEPLOYER_VERSION}/grafana/datasources.yml")
}

pub fn grafana_dashboards_s3_key() -> String {
    format!("{TOOLS_CONFIGS_PREFIX}/{DEPLOYER_VERSION}/grafana/all.yml")
}

pub fn grafana_node_exporter_dashboard_s3_key(version: &str) -> String {
    format!(
        "{TOOLS_CONFIGS_PREFIX}/{DEPLOYER_VERSION}/grafana/node-exporter-full-revision-{version}.json"
    )
}

pub fn loki_config_s3_key() -> String {
    format!("{TOOLS_CONFIGS_PREFIX}/{DEPLOYER_VERSION}/loki/config.yml")
}

pub fn pyroscope_config_s3_key() -> String {
    format!("{TOOLS_CONFIGS_PREFIX}/{DEPLOYER_VERSION}/pyroscope/config.yml")
}

pub fn tempo_config_s3_key() -> String {
    format!("{TOOLS_CONFIGS_PREFIX}/{DEPLOYER_VERSION}/tempo/config.yml")
}

// S3 key functions for pyroscope agent (lives with pyroscope component)

pub fn pyroscope_agent_service_s3_key() -> String {
    format!("{TOOLS_CONFIGS_PREFIX}/{DEPLOYER_VERSION}/pyroscope/agent.service")
}

pub fn pyroscope_agent_timer_s3_key() -> String {
    format!("{TOOLS_CONFIGS_PREFIX}/{DEPLOYER_VERSION}/pyroscope/agent.timer")
}

// S3 key functions for binary instance configs

pub(crate) fn binary_service_s3_key_for_arch(architecture: Architecture) -> String {
    format!(
        "{TOOLS_CONFIGS_PREFIX}/{DEPLOYER_VERSION}/binary/service-{arch}",
        arch = architecture.as_str()
    )
}

/// Returns the S3 key for an instance's binary by digest (deduplicated within deployment)
pub fn binary_s3_key(tag: &str, digest: &str) -> String {
    format!("{DEPLOYMENTS_PREFIX}/{tag}/binaries/{digest}")
}

/// Returns the S3 key for an instance's config by digest (deduplicated within deployment)
pub fn config_s3_key(tag: &str, digest: &str) -> String {
    format!("{DEPLOYMENTS_PREFIX}/{tag}/configs/{digest}")
}

/// Returns the S3 key for hosts.yaml by digest (deduplicated within deployment)
pub fn hosts_s3_key(tag: &str, digest: &str) -> String {
    format!("{DEPLOYMENTS_PREFIX}/{tag}/hosts/{digest}")
}

/// Returns the S3 key for promtail config by digest (deduplicated within deployment)
pub fn promtail_s3_key(tag: &str, digest: &str) -> String {
    format!("{DEPLOYMENTS_PREFIX}/{tag}/promtail/{digest}")
}

/// Returns the S3 key for pyroscope agent script by digest (deduplicated within deployment)
pub fn pyroscope_s3_key(tag: &str, digest: &str) -> String {
    format!("{DEPLOYMENTS_PREFIX}/{tag}/pyroscope/{digest}")
}

/// Returns the S3 key for monitoring config by digest (deduplicated within deployment)
pub fn monitoring_s3_key(tag: &str, digest: &str) -> String {
    format!("{DEPLOYMENTS_PREFIX}/{tag}/monitoring/{digest}")
}

/// Returns the download URL for the Node Exporter Full Grafana dashboard
pub(crate) fn grafana_node_exporter_dashboard_download_url(version: &str) -> String {
    format!("https://grafana.com/api/dashboards/1860/revisions/{version}/download")
}

/// Returns the download URL for Samply from GitHub
pub(crate) fn samply_download_url(version: &str, architecture: Architecture) -> String {
    let arch = match architecture {
        Architecture::Arm64 => "aarch64",
        Architecture::X86_64 => "x86_64",
    };
    format!(
        "https://github.com/mstange/samply/releases/download/samply-v{version}/samply-{arch}-unknown-linux-gnu.tar.xz"
    )
}

/// Returns the download URL for Docker static binaries
pub(crate) fn docker_download_url(version: &str, architecture: Architecture) -> String {
    format!(
        "https://download.docker.com/linux/static/stable/{arch}/docker-{version}.tgz",
        arch = docker_static_arch(architecture)
    )
}

const fn docker_static_arch(architecture: Architecture) -> &'static str {
    match architecture {
        Architecture::Arm64 => "aarch64",
        Architecture::X86_64 => "x86_64",
    }
}

/// Returns the download URL for libjemalloc2 from Ubuntu archive
pub(crate) fn libjemalloc_download_url(version: &str, architecture: Architecture) -> String {
    let base = match architecture {
        Architecture::Arm64 => UBUNTU_ARCHIVE_ARM64,
        Architecture::X86_64 => UBUNTU_ARCHIVE_X86_64,
    };
    format!(
        "{base}/universe/j/jemalloc/libjemalloc2_{version}_{arch}.deb",
        arch = architecture.as_str()
    )
}

/// Returns the download URL for logrotate from Ubuntu archive
pub(crate) fn logrotate_download_url(version: &str, architecture: Architecture) -> String {
    let base = match architecture {
        Architecture::Arm64 => UBUNTU_ARCHIVE_ARM64,
        Architecture::X86_64 => UBUNTU_ARCHIVE_X86_64,
    };
    format!(
        "{base}/main/l/logrotate/logrotate_{version}_{arch}.deb",
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

/// YAML configuration for Tempo
pub const TEMPO_CONFIG: &str = r#"
server:
  grpc_listen_port: 9096
  grpc_server_max_recv_msg_size: 104857600
  grpc_server_max_send_msg_size: 104857600
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
      path: /var/tempo/traces
    wal:
      path: /var/tempo/wal
ingester:
  max_block_duration: 1h
compactor:
  compaction:
    block_retention: 1h
    compaction_cycle: 1h
overrides:
  defaults:
    ingestion:
      rate_limit_bytes: 1000000000
      burst_size_bytes: 2000000000
      max_traces_per_user: 500000
    global:
      max_bytes_per_trace: 100000000
"#;

/// URLs for monitoring service installation
pub struct MonitoringUrls {
    pub docker_tgz: String,
    pub prometheus_config: String,
    pub datasources_yml: String,
    pub all_yml: String,
    pub dashboard: String,
    pub node_exporter_dashboard: String,
    pub loki_yml: String,
    pub pyroscope_yml: String,
    pub tempo_yml: String,
    pub images: Vec<(&'static str, String)>,
}

/// Builds the concurrent download + verify block for the per-architecture image tarballs.
fn image_download_block(images: &[(&'static str, String)]) -> String {
    if images.is_empty() {
        return String::new();
    }
    let mut cmd = String::from(
        "\n# Download container image tarballs from S3 concurrently via pre-signed URLs\nmkdir -p /home/ubuntu/images\nrm -f /home/ubuntu/images/*.tar.gz\n",
    );
    let mut files = Vec::new();
    for (image, url) in images {
        let file = image_file_name(image);
        cmd.push_str(WGET);
        cmd.push_str(" -O /home/ubuntu/images/");
        cmd.push_str(&file);
        cmd.push_str(" '");
        cmd.push_str(url);
        cmd.push_str("' &\n");
        files.push(file);
    }
    cmd.push_str("wait\n");
    cmd.push_str("for f in");
    for file in &files {
        cmd.push(' ');
        cmd.push_str(file);
    }
    cmd.push_str(
        "; do\n    if [ ! -s \"/home/ubuntu/images/$f\" ]; then\n        echo \"ERROR: Failed to download image $f\" >&2\n        exit 1\n    fi\ndone\n",
    );
    cmd
}

/// Phase 1: Download files from S3 on monitoring instance
pub(crate) fn install_monitoring_download_cmd(urls: &MonitoringUrls) -> String {
    let mut cmd = format!(
        r#"
# Clean up any previous download artifacts (allows retries to re-download fresh copies)
rm -f /home/ubuntu/prometheus.yml /home/ubuntu/datasources.yml /home/ubuntu/all.yml \
      /home/ubuntu/dashboard.json /home/ubuntu/node-exporter-full.json /home/ubuntu/loki.yml \
      /home/ubuntu/pyroscope.yml /home/ubuntu/tempo.yml /home/ubuntu/docker.tgz

# Unmask services in case previous attempt left them masked
sudo systemctl unmask docker prometheus loki pyroscope tempo node_exporter grafana tracer 2>/dev/null || true

# Download all files from S3 concurrently via pre-signed URLs
{WGET} -O /home/ubuntu/docker.tgz '{}' &
{WGET} -O /home/ubuntu/prometheus.yml '{}' &
{WGET} -O /home/ubuntu/datasources.yml '{}' &
{WGET} -O /home/ubuntu/all.yml '{}' &
{WGET} -O /home/ubuntu/dashboard.json '{}' &
{WGET} -O /home/ubuntu/node-exporter-full.json '{}' &
{WGET} -O /home/ubuntu/loki.yml '{}' &
{WGET} -O /home/ubuntu/pyroscope.yml '{}' &
{WGET} -O /home/ubuntu/tempo.yml '{}' &
wait

# Verify all downloads succeeded
for f in prometheus.yml datasources.yml all.yml dashboard.json node-exporter-full.json \
         loki.yml pyroscope.yml tempo.yml docker.tgz; do
    if [ ! -f "/home/ubuntu/$f" ]; then
        echo "ERROR: Failed to download $f" >&2
        exit 1
    fi
done
"#,
        urls.docker_tgz,
        urls.prometheus_config,
        urls.datasources_yml,
        urls.all_yml,
        urls.dashboard,
        urls.node_exporter_dashboard,
        urls.loki_yml,
        urls.pyroscope_yml,
        urls.tempo_yml,
    );
    cmd.push_str(&image_download_block(&urls.images));
    cmd
}

fn install_image_services_cmd(services: &'static [ImageService]) -> String {
    if services.is_empty() {
        return String::new();
    }

    let mut cmd = String::from(
        r#"# Install Docker services
rm -rf /home/ubuntu/docker
tar xzf /home/ubuntu/docker.tgz -C /home/ubuntu
sudo install -m 0755 /home/ubuntu/docker/* /usr/local/bin/
sudo tee /etc/systemd/system/docker.service >/dev/null <<'EOF'
[Unit]
Description=Docker Application Container Engine
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ExecStart=/usr/local/bin/dockerd --host=unix:///var/run/docker.sock
ExecReload=/bin/kill -s HUP $MAINPID
TimeoutStartSec=120
Restart=always
RestartSec=2
Delegate=yes
KillMode=process
LimitNOFILE=infinity
LimitNPROC=infinity
LimitCORE=infinity
TasksMax=infinity
OOMScoreAdjust=-500

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now docker
"#,
    );
    // Load the container images from the tarballs downloaded from S3 (`docker load` auto-detects
    // the gzip compression).
    for image in distinct_images(services) {
        cmd.push_str("sudo docker load -i /home/ubuntu/images/");
        cmd.push_str(&image_file_name(image));
        cmd.push('\n');
    }

    for service in services {
        cmd.push_str("sudo tee /etc/systemd/system/");
        cmd.push_str(service.service);
        cmd.push_str(".service >/dev/null <<'EOF'\n");
        cmd.push_str(&service.service_file());
        cmd.push_str("EOF\n");
    }

    cmd
}

pub(crate) fn monitoring_image_services() -> impl Iterator<Item = &'static str> {
    MONITORING_IMAGE_SERVICES
        .iter()
        .map(|service| service.service)
}

pub(crate) fn binary_image_services() -> impl Iterator<Item = &'static str> {
    BINARY_IMAGE_SERVICES.iter().map(|service| service.service)
}

/// Phase 2: Setup services on monitoring instance (does not start them)
pub(crate) fn install_monitoring_setup_cmd() -> String {
    let image_services = install_image_services_cmd(MONITORING_IMAGE_SERVICES);
    format!(
        r#"set -e

# Enable BBR congestion control
echo -e "net.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr" | sudo tee /etc/sysctl.d/99-bbr.conf >/dev/null && sudo sysctl -p /etc/sysctl.d/99-bbr.conf

{image_services}

# Create service directories
sudo mkdir -p /opt/prometheus /opt/prometheus/data
sudo mkdir -p /loki/index /loki/index_cache /loki/chunks /loki/compactor /loki/wal
sudo mkdir -p /var/lib/pyroscope
sudo mkdir -p /tempo/traces /tempo/wal
sudo mkdir -p /etc/grafana/provisioning/datasources /etc/grafana/provisioning/dashboards /var/lib/grafana/dashboards

# Install configuration files
sudo mv /home/ubuntu/prometheus.yml /opt/prometheus/prometheus.yml
sudo mv /home/ubuntu/datasources.yml /etc/grafana/provisioning/datasources/datasources.yml
sudo mv /home/ubuntu/all.yml /etc/grafana/provisioning/dashboards/all.yml
sudo mv /home/ubuntu/dashboard.json /var/lib/grafana/dashboards/dashboard.json
sudo mv /home/ubuntu/node-exporter-full.json /var/lib/grafana/dashboards/node-exporter-full.json
sudo mkdir -p /etc/loki
sudo mv /home/ubuntu/loki.yml /etc/loki/loki.yml
sudo chown root:root /etc/loki/loki.yml
sudo mkdir -p /etc/pyroscope
sudo mv /home/ubuntu/pyroscope.yml /etc/pyroscope/pyroscope.yml
sudo chown root:root /etc/pyroscope/pyroscope.yml
sudo mkdir -p /etc/tempo
sudo mv /home/ubuntu/tempo.yml /etc/tempo/tempo.yml
sudo chown root:root /etc/tempo/tempo.yml
"#,
    )
}

/// Continuation of monitoring install command (services startup)
pub(crate) fn start_monitoring_services_cmd() -> String {
    let mut cmd = String::from(
        r#"set -e

# Start services
sudo systemctl daemon-reload
"#,
    );

    for service in monitoring_image_services() {
        cmd.push_str("sudo systemctl start ");
        cmd.push_str(service);
        cmd.push('\n');
        cmd.push_str("sudo systemctl enable ");
        cmd.push_str(service);
        cmd.push('\n');
    }

    cmd
}

/// URLs for binary instance installation
pub struct InstanceUrls {
    pub binary: String,
    pub config: String,
    pub hosts: String,
    pub promtail_config: String,
    pub binary_service: String,
    pub pyroscope_script: String,
    pub pyroscope_service: String,
    pub pyroscope_timer: String,
    pub docker_tgz: String,
    pub libjemalloc_deb: String,
    pub logrotate_deb: String,
    pub images: Vec<(&'static str, String)>,
}

/// Phase 1 (optional): Install apt packages on binary instances
/// Only needed when profiling is enabled or NVMe instance-store devices are mounted.
pub(crate) fn install_binary_apt_cmd(profiling: bool, nvme: bool) -> Option<String> {
    let mut packages = Vec::new();
    if profiling {
        packages.extend([
            "linux-tools-common",
            "linux-tools-generic",
            "linux-tools-$(uname -r)",
        ]);
    }
    if nvme {
        packages.push("mdadm");
    }
    if packages.is_empty() {
        return None;
    }

    Some(format!(
        r#"set -e
sudo apt-get update -y
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y {}
"#,
        packages.join(" ")
    ))
}

/// Phase 2: Download files from S3 on binary instances
pub(crate) fn install_binary_download_cmd(urls: &InstanceUrls) -> String {
    let mut cmd = format!(
        r#"
# Clean up any previous download artifacts (allows retries to re-download fresh copies)
rm -f /home/ubuntu/binary /home/ubuntu/config.conf /home/ubuntu/hosts.yaml \
      /home/ubuntu/promtail.yml /home/ubuntu/binary.service \
      /home/ubuntu/pyroscope-agent.sh /home/ubuntu/pyroscope-agent.service \
      /home/ubuntu/pyroscope-agent.timer /home/ubuntu/docker.tgz /home/ubuntu/libjemalloc2.deb \
      /home/ubuntu/logrotate.deb

# Unmask services in case previous attempt left them masked
sudo systemctl unmask docker promtail node_exporter binary 2>/dev/null || true

# Download all files from S3 concurrently via pre-signed URLs
{WGET} -O /home/ubuntu/binary '{}' &
{WGET} -O /home/ubuntu/config.conf '{}' &
{WGET} -O /home/ubuntu/hosts.yaml '{}' &
{WGET} -O /home/ubuntu/promtail.yml '{}' &
{WGET} -O /home/ubuntu/binary.service '{}' &
{WGET} -O /home/ubuntu/pyroscope-agent.sh '{}' &
{WGET} -O /home/ubuntu/pyroscope-agent.service '{}' &
{WGET} -O /home/ubuntu/pyroscope-agent.timer '{}' &
{WGET} -O /home/ubuntu/docker.tgz '{}' &
{WGET} -O /home/ubuntu/libjemalloc2.deb '{}' &
{WGET} -O /home/ubuntu/logrotate.deb '{}' &
wait

# Verify all downloads succeeded
for f in binary config.conf hosts.yaml promtail.yml binary.service \
         pyroscope-agent.sh pyroscope-agent.service pyroscope-agent.timer \
         docker.tgz libjemalloc2.deb logrotate.deb; do
    if [ ! -f "/home/ubuntu/$f" ]; then
        echo "ERROR: Failed to download $f" >&2
        exit 1
    fi
done
"#,
        urls.binary,
        urls.config,
        urls.hosts,
        urls.promtail_config,
        urls.binary_service,
        urls.pyroscope_script,
        urls.pyroscope_service,
        urls.pyroscope_timer,
        urls.docker_tgz,
        urls.libjemalloc_deb,
        urls.logrotate_deb,
    );
    cmd.push_str(&image_download_block(&urls.images));
    cmd
}

/// Returns a command that mounts EC2 NVMe instance-store storage at the binary working directory.
pub(crate) fn nvme_setup_cmd() -> String {
    format!(
        r#"
set -e
cd /

# Configure EC2 NVMe instance-store mounting
NVME_MOUNT='{mount_directory}'
sudo udevadm settle || true
NVME_DEVICES="$(for model_path in /sys/block/nvme*n1/device/model; do
    [ -e "$model_path" ] || continue
    if grep -q 'Amazon EC2 NVMe Instance Storage' "$model_path"; then
        basename "$(dirname "$(dirname "$model_path")")" | sed 's#^#/dev/#'
    fi
done | sort)"
NVME_COUNT="$(printf '%s\n' "$NVME_DEVICES" | sed '/^$/d' | wc -l)"

if [ "$NVME_COUNT" -eq 0 ]; then
    echo "ERROR: NVMe instance storage requested but no EC2 NVMe instance-store devices were found" >&2
    exit 1
fi

sudo mkdir -p "$NVME_MOUNT"

if [ "$NVME_COUNT" -eq 1 ]; then
    NVME_TARGET="$(printf '%s\n' "$NVME_DEVICES" | head -n1)"
else
    NVME_TARGET=/dev/md/commonware-nvme
    sudo mkdir -p /dev/md
    sudo mdadm --assemble "$NVME_TARGET" $NVME_DEVICES >/dev/null 2>&1 || true
    if [ ! -e "$NVME_TARGET" ]; then
        sudo mdadm --create "$NVME_TARGET" --name=commonware-nvme --level=0 --raid-devices="$NVME_COUNT" --force $NVME_DEVICES
    fi
    sudo udevadm settle || true
fi

if ! sudo blkid "$NVME_TARGET" >/dev/null 2>&1; then
    sudo mkfs.ext4 -F "$NVME_TARGET"
fi
if ! findmnt -rn --mountpoint "$NVME_MOUNT" >/dev/null; then
    NVME_STAGE="$(mktemp -d /tmp/commonware-nvme.XXXXXX)"
    cleanup_stage() {{
        if [ -n "${{NVME_STAGE:-}}" ]; then
            sudo umount "$NVME_STAGE" >/dev/null 2>&1 || true
            sudo rmdir "$NVME_STAGE" >/dev/null 2>&1 || true
        fi
    }}
    trap cleanup_stage EXIT
    sudo mount "$NVME_TARGET" "$NVME_STAGE"
    sudo tar -C "$NVME_MOUNT" -cpf - . | sudo tar -C "$NVME_STAGE" -xpf -
    sudo umount "$NVME_STAGE"
    sudo rmdir "$NVME_STAGE"
    NVME_STAGE=
    sudo mount "$NVME_TARGET" "$NVME_MOUNT"
fi

NVME_MOUNT_SOURCE="$(findmnt -rn --mountpoint "$NVME_MOUNT" -o SOURCE || true)"
if [ -z "$NVME_MOUNT_SOURCE" ]; then
    echo "ERROR: NVMe instance storage was not mounted at $NVME_MOUNT" >&2
    exit 1
fi
if [ "$(readlink -f "$NVME_MOUNT_SOURCE")" != "$(readlink -f "$NVME_TARGET")" ]; then
    echo "ERROR: $NVME_MOUNT is mounted from $NVME_MOUNT_SOURCE, expected $NVME_TARGET" >&2
    exit 1
fi

sudo chown -R ubuntu:ubuntu "$NVME_MOUNT"
"#,
        mount_directory = HOME_DIRECTORY,
    )
}

/// Phase 3: Setup and start services on binary instances
pub(crate) fn install_binary_setup_cmd(profiling: bool, _architecture: Architecture) -> String {
    let image_services = install_image_services_cmd(BINARY_IMAGE_SERVICES);
    let perf_setup = if profiling {
        r#"
# Setup pyroscope agent (perf symlink must be created after linux-tools installed via apt)
sudo ln -sf "$(find /usr/lib/linux-tools/*/perf | head -1)" /usr/local/bin/perf
sudo chmod +x /home/ubuntu/pyroscope-agent.sh
sudo mv /home/ubuntu/pyroscope-agent.service /etc/systemd/system/pyroscope-agent.service
sudo mv /home/ubuntu/pyroscope-agent.timer /etc/systemd/system/pyroscope-agent.timer
"#
    } else {
        ""
    };
    let pyroscope_enable = if profiling {
        "\nsudo systemctl enable --now pyroscope-agent.timer\n"
    } else {
        ""
    };
    format!(
        r#"set -e

# Enable BBR congestion control
echo -e "net.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr" | sudo tee /etc/sysctl.d/99-bbr.conf >/dev/null && sudo sysctl -p /etc/sysctl.d/99-bbr.conf

{image_services}

# Install deb packages
sudo dpkg -i /home/ubuntu/libjemalloc2.deb
sudo dpkg -i /home/ubuntu/logrotate.deb

# Setup Promtail
sudo mkdir -p /etc/promtail /var/lib/promtail
sudo mv /home/ubuntu/promtail.yml /etc/promtail/promtail.yml
sudo chown root:root /etc/promtail/promtail.yml

# Setup binary
chmod +x /home/ubuntu/binary
sudo touch /var/log/binary.log && sudo chown ubuntu:ubuntu /var/log/binary.log
sudo mv /home/ubuntu/binary.service /etc/systemd/system/binary.service

# Setup logrotate
sudo tee /etc/logrotate.d/binary >/dev/null <<'EOF'
{LOGROTATE_CONF}EOF
echo "0 * * * * /usr/sbin/logrotate /etc/logrotate.d/binary" | crontab -

{perf_setup}
# Start services
sudo systemctl daemon-reload
sudo systemctl enable node_exporter
sudo systemctl enable promtail
sudo systemctl enable binary
sudo systemctl start node_exporter
sudo systemctl start promtail
sudo systemctl start binary{pyroscope_enable}"#
    )
}

/// Generates Promtail configuration with the monitoring instance's private IP and instance name
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
  filename: /var/lib/promtail/positions.yaml
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

/// Generates Prometheus configuration with scrape targets for all instance IPs
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
"#
        ));
        config.push_str(&format!(
            r#"
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

# Construct the Pyroscope application name with tags (URL-encoded)
RAW_APP_NAME="binary{{deployer_name={name},deployer_ip={ip},deployer_region={region},deployer_arch={arch}}}"
APP_NAME=$(printf '%s' "$RAW_APP_NAME" | python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.stdin.read()))")

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

    fn monitoring_urls() -> MonitoringUrls {
        MonitoringUrls {
            docker_tgz: "docker".to_string(),
            prometheus_config: "prometheus-config".to_string(),
            datasources_yml: "datasources".to_string(),
            all_yml: "dashboards".to_string(),
            dashboard: "dashboard".to_string(),
            node_exporter_dashboard: "node-exporter-dashboard".to_string(),
            loki_yml: "loki-config".to_string(),
            pyroscope_yml: "pyroscope-config".to_string(),
            tempo_yml: "tempo-config".to_string(),
            images: monitoring_images()
                .map(|image| (image, format!("image-url-{image}")))
                .collect(),
        }
    }

    fn instance_urls() -> InstanceUrls {
        InstanceUrls {
            binary: "binary".to_string(),
            config: "config".to_string(),
            hosts: "hosts".to_string(),
            promtail_config: "promtail-config".to_string(),
            binary_service: "binary-service".to_string(),
            pyroscope_script: "pyroscope-script".to_string(),
            pyroscope_service: "pyroscope-service".to_string(),
            pyroscope_timer: "pyroscope-timer".to_string(),
            docker_tgz: "docker".to_string(),
            libjemalloc_deb: "libjemalloc".to_string(),
            logrotate_deb: "logrotate".to_string(),
            images: binary_images()
                .map(|image| (image, format!("image-url-{image}")))
                .collect(),
        }
    }

    #[test]
    fn test_binary_s3_keys_arm64() {
        let arch = Architecture::Arm64;
        assert_eq!(
            docker_bin_s3_key("29.6.0", arch),
            "tools/binaries/docker/29.6.0/linux-aarch64/docker-29.6.0.tgz"
        );
        assert_eq!(
            samply_bin_s3_key("0.13.1", arch),
            "tools/binaries/samply/0.13.1/linux-aarch64/samply-aarch64-unknown-linux-gnu.tar.xz"
        );
        assert_eq!(
            libjemalloc_bin_s3_key("5.3.0-2build1", arch),
            "tools/binaries/libjemalloc2/5.3.0-2build1/linux-arm64/libjemalloc2_5.3.0-2build1_arm64.deb"
        );
        assert_eq!(
            logrotate_bin_s3_key("3.21.0-2build1", arch),
            "tools/binaries/logrotate/3.21.0-2build1/linux-arm64/logrotate_3.21.0-2build1_arm64.deb"
        );
    }

    #[test]
    fn test_binary_s3_keys_x86_64() {
        let arch = Architecture::X86_64;
        assert_eq!(
            docker_bin_s3_key("29.6.0", arch),
            "tools/binaries/docker/29.6.0/linux-x86_64/docker-29.6.0.tgz"
        );
        assert_eq!(
            samply_bin_s3_key("0.13.1", arch),
            "tools/binaries/samply/0.13.1/linux-x86_64/samply-x86_64-unknown-linux-gnu.tar.xz"
        );
        assert_eq!(
            libjemalloc_bin_s3_key("5.3.0-2build1", arch),
            "tools/binaries/libjemalloc2/5.3.0-2build1/linux-amd64/libjemalloc2_5.3.0-2build1_amd64.deb"
        );
        assert_eq!(
            logrotate_bin_s3_key("3.21.0-2build1", arch),
            "tools/binaries/logrotate/3.21.0-2build1/linux-amd64/logrotate_3.21.0-2build1_amd64.deb"
        );
    }

    #[test]
    fn test_config_s3_keys() {
        let version = DEPLOYER_VERSION;

        assert_eq!(
            grafana_datasources_s3_key(),
            format!("tools/configs/{version}/grafana/datasources.yml")
        );
        assert_eq!(
            grafana_dashboards_s3_key(),
            format!("tools/configs/{version}/grafana/all.yml")
        );
        assert_eq!(
            grafana_node_exporter_dashboard_s3_key(GRAFANA_NODE_EXPORTER_DASHBOARD_VERSION),
            format!("tools/configs/{version}/grafana/node-exporter-full-revision-{GRAFANA_NODE_EXPORTER_DASHBOARD_VERSION}.json")
        );
        assert_eq!(
            loki_config_s3_key(),
            format!("tools/configs/{version}/loki/config.yml")
        );
        assert_eq!(
            pyroscope_config_s3_key(),
            format!("tools/configs/{version}/pyroscope/config.yml")
        );
        assert_eq!(
            tempo_config_s3_key(),
            format!("tools/configs/{version}/tempo/config.yml")
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
            binary_service_s3_key_for_arch(Architecture::Arm64),
            format!("tools/configs/{version}/binary/service-arm64")
        );
        assert_eq!(
            binary_service_s3_key_for_arch(Architecture::X86_64),
            format!("tools/configs/{version}/binary/service-amd64")
        );
    }

    #[test]
    fn test_monitoring_installs_node_exporter_dashboard() {
        let urls = monitoring_urls();
        let download = install_monitoring_download_cmd(&urls);
        assert!(download.contains("-O /home/ubuntu/docker.tgz"));
        assert!(download.contains("-O /home/ubuntu/node-exporter-full.json"));
        assert!(download.contains("node-exporter-dashboard"));
        assert!(download.contains("node-exporter-full.json"));

        let setup = install_monitoring_setup_cmd();
        assert!(setup.contains(
            "sudo mv /home/ubuntu/dashboard.json /var/lib/grafana/dashboards/dashboard.json"
        ));
        assert!(setup.contains("sudo mv /home/ubuntu/node-exporter-full.json /var/lib/grafana/dashboards/node-exporter-full.json"));
    }

    #[test]
    fn test_monitoring_installs_image_services() {
        let urls = monitoring_urls();
        let download = install_monitoring_download_cmd(&urls);
        assert!(!download.contains("tracer.service"));
        assert!(!download.contains("prometheus.tar.gz"));
        assert!(!download.contains("grafana.deb"));
        assert!(!download.contains("node_exporter.tar.gz"));
        assert!(download.contains(&format!(
            "-O /home/ubuntu/images/{}",
            image_file_name(TRACER_IMAGE)
        )));
        assert!(download.contains(&format!(
            "-O /home/ubuntu/images/{}",
            image_file_name(PROMETHEUS_IMAGE)
        )));

        let setup = install_monitoring_setup_cmd();
        assert!(setup.contains("# Install Docker services"));
        assert!(setup.contains("tar xzf /home/ubuntu/docker.tgz -C /home/ubuntu"));
        assert!(
            setup.contains("ExecStart=/usr/local/bin/dockerd --host=unix:///var/run/docker.sock")
        );
        assert!(setup.contains("ExecStartPre=-/usr/local/bin/docker rm -f tracer"));
        assert!(setup.contains("ExecStart=/usr/local/bin/docker run --rm --name tracer"));
        assert!(!setup.contains("/usr/bin/docker"));
        assert!(!setup.contains("apt-get install -y docker.io"));
        assert!(!setup.contains("docker pull"));
        assert!(!setup.contains("docker login"));
        for image in [
            PROMETHEUS_IMAGE,
            LOKI_IMAGE,
            PYROSCOPE_IMAGE,
            TEMPO_IMAGE,
            GRAFANA_IMAGE,
            NODE_EXPORTER_IMAGE,
            TRACER_IMAGE,
        ] {
            assert!(setup.contains(&format!(
                "sudo docker load -i /home/ubuntu/images/{}",
                image_file_name(image)
            )));
        }
        assert!(setup.contains("sudo tee /etc/systemd/system/tracer.service"));
        assert!(setup.contains("sudo tee /etc/systemd/system/grafana.service"));

        let start = start_monitoring_services_cmd();
        for service in monitoring_image_services() {
            assert!(start.contains(&format!("sudo systemctl start {service}")));
            assert!(start.contains(&format!("sudo systemctl enable {service}")));
        }

        assert!(setup.contains(&format!(
            "--env TEMPO_URL=http://127.0.0.1:3200 {TRACER_IMAGE}"
        )));
        assert!(setup.contains("--network host"));
        assert!(setup.contains("--volume /tempo:/var/tempo"));
        assert!(!setup.contains("--volume /tempo:/tempo"));

        assert!(TEMPO_CONFIG.contains("path: /var/tempo/traces"));
        assert!(TEMPO_CONFIG.contains("path: /var/tempo/wal"));
        assert!(TEMPO_CONFIG.contains("grpc_server_max_recv_msg_size: 104857600"));
        assert!(TEMPO_CONFIG.contains("grpc_server_max_send_msg_size: 104857600"));
        assert!(!TEMPO_CONFIG.contains("path: /tempo/"));
    }

    #[test]
    fn test_prometheus_config_scrapes_binary_metrics_for_all_instances() {
        let config = generate_prometheus_config(&[
            ("validator", "10.0.0.1", "us-east-1", "arm64"),
            ("spammer", "10.0.0.2", "us-east-1", "arm64"),
        ]);

        assert!(config.contains("job_name: 'validator_binary'"));
        assert!(config.contains("targets: ['10.0.0.1:9090']"));
        assert!(config.contains("job_name: 'validator_system'"));
        assert!(config.contains("targets: ['10.0.0.1:9100']"));

        assert!(config.contains("job_name: 'spammer_binary'"));
        assert!(config.contains("targets: ['10.0.0.2:9090']"));
        assert!(config.contains("job_name: 'spammer_system'"));
        assert!(config.contains("targets: ['10.0.0.2:9100']"));
    }

    #[test]
    fn test_binary_installs_image_helpers() {
        let urls = instance_urls();
        let download = install_binary_download_cmd(&urls);
        assert!(download.contains("-O /home/ubuntu/promtail.yml"));
        assert!(download.contains("-O /home/ubuntu/docker.tgz"));
        assert!(download.contains("-O /home/ubuntu/logrotate.deb"));
        assert!(!download.contains("promtail.zip"));
        assert!(!download.contains("node_exporter.tar.gz"));
        assert!(download.contains(&format!(
            "-O /home/ubuntu/images/{}",
            image_file_name(PROMTAIL_IMAGE)
        )));
        assert!(download.contains(&format!(
            "-O /home/ubuntu/images/{}",
            image_file_name(NODE_EXPORTER_IMAGE)
        )));

        let setup = install_binary_setup_cmd(false, Architecture::Arm64);
        assert!(setup.contains(&format!(
            "sudo docker load -i /home/ubuntu/images/{}",
            image_file_name(PROMTAIL_IMAGE)
        )));
        assert!(setup.contains(&format!(
            "sudo docker load -i /home/ubuntu/images/{}",
            image_file_name(NODE_EXPORTER_IMAGE)
        )));
        assert!(!setup.contains("docker pull"));
        assert!(!setup.contains("docker login"));
        assert!(setup.contains("sudo tee /etc/systemd/system/promtail.service"));
        assert!(setup.contains("sudo tee /etc/systemd/system/node_exporter.service"));
        assert!(setup.contains("ExecStartPre=-/usr/local/bin/docker rm -f promtail"));
        assert!(setup.contains("ExecStart=/usr/local/bin/docker run --rm --name promtail"));
        assert!(!setup.contains("/usr/bin/docker"));
        assert!(setup.contains("sudo dpkg -i /home/ubuntu/logrotate.deb"));
        assert!(setup.contains("copytruncate"));
        assert!(setup.contains(
            "echo \"0 * * * * /usr/sbin/logrotate /etc/logrotate.d/binary\" | crontab -"
        ));
        assert!(!setup.contains("binary-log-truncate"));
        assert!(!setup.contains("busybox"));
        assert!(setup.contains("sudo systemctl enable node_exporter"));
        assert!(setup.contains("sudo systemctl enable promtail"));
        assert!(setup.contains("sudo systemctl enable binary"));
        assert!(setup.contains("sudo systemctl start node_exporter"));
        assert!(setup.contains("sudo systemctl start promtail"));
        assert!(setup.contains("sudo systemctl start binary"));
        let node_exporter_start = setup.find("sudo systemctl start node_exporter").unwrap();
        let promtail_start = setup.find("sudo systemctl start promtail").unwrap();
        let binary_start = setup.find("sudo systemctl start binary").unwrap();
        assert!(node_exporter_start < binary_start);
        assert!(promtail_start < binary_start);

        let promtail = promtail_config("10.0.0.1", "worker", "10.0.1.2", "us-east-1", "arm64");
        assert!(promtail.contains("filename: /var/lib/promtail/positions.yaml"));
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
