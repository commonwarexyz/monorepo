//! Service configuration for Prometheus, Loki, Grafana, Promtail, and a caller-provided binary

/// Version of Prometheus to download and install
pub const PROMETHEUS_VERSION: &str = "3.2.0";

/// Version of Promtail to download and install
pub const PROMTAIL_VERSION: &str = "3.4.2";

/// Version of Loki to download and install
pub const LOKI_VERSION: &str = "3.4.2";

/// Version of Pyroscope to download and install
pub const PYROSCOPE_VERSION: &str = "1.12.0";

/// Version of Grafana to download and install
pub const GRAFANA_VERSION: &str = "11.5.2";

/// YAML configuration for Grafana datasources (Prometheus, Loki, and Pyroscope)
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
pub const PROMETHEUS_SERVICE: &str = r#"
[Unit]
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
pub const PROMTAIL_SERVICE: &str = r#"
[Unit]
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
pub const LOKI_SERVICE: &str = r#"
[Unit]
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
"#;

/// Systemd service file content for Pyroscope
pub const PYROSCOPE_SERVICE: &str = r#"
[Unit]
Description=Pyroscope Profiling Service
After=network.target

[Service]
ExecStart=/opt/pyroscope/pyroscope server --config.file=/etc/pyroscope/pyroscope.yml --storage.data-path=/var/lib/pyroscope
TimeoutStopSec=60
Restart=always
User=ubuntu
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
"#;

/// Command to install monitoring services (Prometheus, Loki, Grafana) on the monitoring instance
pub fn install_monitoring_cmd(
    prometheus_version: &str,
    grafana_version: &str,
    loki_version: &str,
    pyroscope_version: &str,
) -> String {
    let prometheus_url = format!(
    "https://github.com/prometheus/prometheus/releases/download/v{}/prometheus-{}.linux-arm64.tar.gz",
    prometheus_version, prometheus_version
);
    let grafana_url = format!(
        "https://dl.grafana.com/oss/release/grafana_{}_arm64.deb",
        grafana_version
    );
    let loki_url = format!(
        "https://github.com/grafana/loki/releases/download/v{}/loki-linux-arm64.zip",
        loki_version
    );
    let pyroscope_url = format!(
      "https://github.com/grafana/pyroscope/releases/download/v{}/pyroscope_{}_linux_arm64.tar.gz",
      pyroscope_version, pyroscope_version
  );
    format!(
        r#"
sudo apt-get update -y
sudo apt-get install -y wget curl unzip adduser libfontconfig1

# Download Prometheus with retries
for i in {{1..5}}; do
  wget -O /home/ubuntu/prometheus.tar.gz {} && break
  sleep 10
done

# Download Grafana with retries
for i in {{1..5}}; do
  wget -O /home/ubuntu/grafana.deb {} && break
  sleep 10
done

# Download Loki with retries
for i in {{1..5}}; do
  wget -O /home/ubuntu/loki.zip {} && break
  sleep 10
done

# Download Pyroscope with retries
for i in {{1..5}}; do
  wget -O /home/ubuntu/pyroscope.tar.gz {} && break
  sleep 10
done

# Install Prometheus
sudo mkdir -p /opt/prometheus /opt/prometheus/data
sudo chown -R ubuntu:ubuntu /opt/prometheus
tar xvfz /home/ubuntu/prometheus.tar.gz -C /home/ubuntu
sudo mv /home/ubuntu/prometheus-{}.linux-arm64 /opt/prometheus/prometheus-{}.linux-arm64
sudo ln -s /opt/prometheus/prometheus-{}.linux-arm64/prometheus /opt/prometheus/prometheus
sudo chmod +x /opt/prometheus/prometheus

# Install Grafana
sudo dpkg -i /home/ubuntu/grafana.deb
sudo apt-get install -f -y

# Install Loki
sudo mkdir -p /opt/loki /loki/index /loki/index_cache /loki/chunks /loki/compactor /loki/wal
sudo chown -R ubuntu:ubuntu /loki
unzip -o /home/ubuntu/loki.zip -d /home/ubuntu
sudo mv /home/ubuntu/loki-linux-arm64 /opt/loki/loki

# Install Pyroscope
sudo mkdir -p /opt/pyroscope /var/lib/pyroscope
sudo chown -R ubuntu:ubuntu /opt/pyroscope /var/lib/pyroscope
tar xvfz /home/ubuntu/pyroscope.tar.gz -C /home/ubuntu
sudo mv /home/ubuntu/pyroscope /opt/pyroscope/pyroscope
sudo chmod +x /opt/pyroscope/pyroscope

# Configure Grafana
sudo sed -i '/^\[auth.anonymous\]$/,/^\[/ {{ /^; *enabled = /s/.*/enabled = true/; /^; *org_role = /s/.*/org_role = Admin/ }}' /etc/grafana/grafana.ini
sudo mkdir -p /etc/grafana/provisioning/datasources /etc/grafana/provisioning/dashboards /var/lib/grafana/dashboards

# Install Pyroscope data source plugin
sudo grafana-cli plugins install grafana-pyroscope-datasource

# Move configuration files (assuming they are uploaded via SCP)
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

# Move service files
sudo mv /home/ubuntu/prometheus.service /etc/systemd/system/prometheus.service
sudo mv /home/ubuntu/loki.service /etc/systemd/system/loki.service
sudo mv /home/ubuntu/pyroscope.service /etc/systemd/system/pyroscope.service

# Set ownership
sudo chown -R grafana:grafana /etc/grafana /var/lib/grafana

# Start services
sudo systemctl daemon-reload
sudo systemctl start prometheus
sudo systemctl enable prometheus
sudo systemctl start loki
sudo systemctl enable loki
sudo systemctl start pyroscope
sudo systemctl enable pyroscope
sudo systemctl restart grafana-server
sudo systemctl enable grafana-server
"#,
        prometheus_url,
        grafana_url,
        loki_url,
        pyroscope_url,
        prometheus_version,
        prometheus_version,
        prometheus_version
    )
}

/// Command to install the binary on binary instances
pub const INSTALL_BINARY_CMD: &str = r#"
chmod +x /home/ubuntu/binary
sudo touch /var/log/binary.log && sudo chown ubuntu:ubuntu /var/log/binary.log
sudo mv /home/ubuntu/binary.service /etc/systemd/system/binary.service
sudo apt-get update -y
sudo apt-get install -y logrotate
sudo mv /home/ubuntu/logrotate.conf /etc/logrotate.d/binary
sudo chown root:root /etc/logrotate.d/binary
echo "0 * * * * /usr/sbin/logrotate /etc/logrotate.d/binary" | crontab -
sudo systemctl daemon-reload
sudo systemctl start binary
sudo systemctl enable binary
"#;

/// Command to set up Promtail on binary instances
pub fn setup_promtail_cmd(promtail_version: &str) -> String {
    let promtail_url = format!(
        "https://github.com/grafana/loki/releases/download/v{}/promtail-linux-arm64.zip",
        promtail_version
    );
    format!(
        r#"
sudo apt-get update -y
sudo apt-get install -y wget unzip

# Download Promtail with retries
for i in {{1..5}}; do
  wget -O /home/ubuntu/promtail.zip {} && break
  sleep 10
done

sudo mkdir -p /opt/promtail
unzip /home/ubuntu/promtail.zip -d /home/ubuntu
sudo mv /home/ubuntu/promtail-linux-arm64 /opt/promtail/promtail
sudo chmod +x /opt/promtail/promtail
sudo mkdir -p /etc/promtail
sudo mv /home/ubuntu/promtail.yml /etc/promtail/promtail.yml
sudo mv /home/ubuntu/promtail.service /etc/systemd/system/promtail.service
sudo chown root:root /etc/promtail/promtail.yml
sudo systemctl daemon-reload
sudo systemctl start promtail
sudo systemctl enable promtail
"#,
        promtail_url
    )
}

/// Generates Promtail configuration with the monitoring instance's private IP and instance name
pub fn promtail_config(
    monitoring_private_ip: &str,
    instance_name: &str,
    ip: &str,
    region: &str,
) -> String {
    format!(
        r#"
server:
  http_listen_port: 9080
  grpc_listen_port: 0
positions:
  filename: /tmp/positions.yaml
clients:
  - url: http://{}:3100/loki/api/v1/push
scrape_configs:
  - job_name: binary_logs
    static_configs:
      - targets:
          - localhost
        labels:
          job: binary
          instance: {}
          ip: {}
          region: {}
          __path__: /var/log/binary.log
      "#,
        monitoring_private_ip, instance_name, ip, region
    )
}

/// Generates Prometheus configuration with scrape targets for all instance IPs
pub fn generate_prometheus_config(instances: &[(&str, &str, &str)]) -> String {
    let mut config = String::from(
        r#"
global:
  scrape_interval: 15s
scrape_configs:
"#,
    );
    for (name, ip, region) in instances {
        config.push_str(&format!(
            r#"
  - job_name: '{}'
    static_configs:
      - targets: ['{}:9090']
        labels:
          region: '{}'
"#,
            name, ip, region
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

/// Systemd service file content for the deployed binary
pub const BINARY_SERVICE: &str = r#"
[Unit]
Description=Deployed Binary Service
After=network.target

[Service]
ExecStart=/home/ubuntu/binary --peers=/home/ubuntu/peers.yaml --config=/home/ubuntu/config.conf
TimeoutStopSec=60
Restart=always
User=ubuntu
LimitNOFILE=infinity
StandardOutput=append:/var/log/binary.log
StandardError=append:/var/log/binary.log

[Install]
WantedBy=multi-user.target
"#;
