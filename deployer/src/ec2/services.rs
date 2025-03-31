//! Service configuration for Prometheus, Loki, Grafana, Promtail, and a caller-provided binary

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
pub const PYROSCOPE_SERVICE: &str = r#"
[Unit]
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
pub const TEMPO_SERVICE: &str = r#"
[Unit]
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

/// Command to install monitoring services (Prometheus, Loki, Grafana) on the monitoring instance
pub fn install_monitoring_cmd(
    prometheus_version: &str,
    grafana_version: &str,
    loki_version: &str,
    pyroscope_version: &str,
    tempo_version: &str,
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
    let tempo_url = format!(
        "https://github.com/grafana/tempo/releases/download/v{}/tempo_{}_linux_arm64.tar.gz",
        tempo_version, tempo_version
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

# Download Tempo with retries
for i in {{1..5}}; do
  wget -O /home/ubuntu/tempo.tar.gz {} && break
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

# Install Tempo
sudo mkdir -p /opt/tempo /tempo/traces /tempo/wal
sudo chown -R ubuntu:ubuntu /tempo
tar xvfz /home/ubuntu/tempo.tar.gz -C /home/ubuntu
sudo mv /home/ubuntu/tempo /opt/tempo/tempo
sudo chmod +x /opt/tempo/tempo

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
sudo mkdir -p /etc/tempo
sudo mv /home/ubuntu/tempo.yml /etc/tempo/tempo.yml
sudo chown root:root /etc/tempo/tempo.yml

# Move service files
sudo mv /home/ubuntu/prometheus.service /etc/systemd/system/prometheus.service
sudo mv /home/ubuntu/loki.service /etc/systemd/system/loki.service
sudo mv /home/ubuntu/pyroscope.service /etc/systemd/system/pyroscope.service
sudo mv /home/ubuntu/tempo.service /etc/systemd/system/tempo.service

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
sudo systemctl start tempo
sudo systemctl enable tempo
sudo systemctl restart grafana-server
sudo systemctl enable grafana-server
"#,
        prometheus_url,
        grafana_url,
        loki_url,
        pyroscope_url,
        tempo_url,
        prometheus_version,
        prometheus_version,
        prometheus_version
    )
}

/// Command to install the binary on binary instances
pub fn install_binary_cmd(profiling: bool) -> String {
    let mut script = String::from(
        r#"
# Install base tools and binary dependencies
sudo apt-get update -y
sudo apt-get install -y logrotate wget bpfcc-tools linux-headers-$(uname -r)

# Setup binary
chmod +x /home/ubuntu/binary
sudo touch /var/log/binary.log && sudo chown ubuntu:ubuntu /var/log/binary.log
sudo mv /home/ubuntu/binary.service /etc/systemd/system/binary.service

# Setup logrotate
sudo mv /home/ubuntu/logrotate.conf /etc/logrotate.d/binary
sudo chown root:root /etc/logrotate.d/binary
echo "0 * * * * /usr/sbin/logrotate /etc/logrotate.d/binary" | crontab -

# Setup pyroscope agent script and timer
sudo chmod +x /home/ubuntu/pyroscope-agent.sh
sudo mv /home/ubuntu/pyroscope-agent.service /etc/systemd/system/pyroscope-agent.service
sudo mv /home/ubuntu/pyroscope-agent.timer /etc/systemd/system/pyroscope-agent.timer

# Setup memleak agent script and timer
sudo chmod +x /home/ubuntu/memleak-agent.sh
sudo mv /home/ubuntu/memleak-agent.service /etc/systemd/system/memleak-agent.service

# Start services
sudo systemctl daemon-reload
sudo systemctl enable --now binary
"#,
    );
    if profiling {
        script.push_str(
            r#"
sudo systemctl enable --now pyroscope-agent.timer
sudo systemctl enable --now memleak-agent
"#,
        );
    }
    script
}

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

# Install Promtail
sudo mkdir -p /opt/promtail
unzip /home/ubuntu/promtail.zip -d /home/ubuntu
sudo mv /home/ubuntu/promtail-linux-arm64 /opt/promtail/promtail
sudo chmod +x /opt/promtail/promtail
sudo mkdir -p /etc/promtail
sudo mv /home/ubuntu/promtail.yml /etc/promtail/promtail.yml
sudo mv /home/ubuntu/promtail.service /etc/systemd/system/promtail.service
sudo chown root:root /etc/promtail/promtail.yml

# Start service
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
          deployer_name: {}
          deployer_ip: {}
          deployer_region: {}
          __path__: /var/log/binary.log
      "#,
        monitoring_private_ip, instance_name, ip, region
    )
}

/// Command to install Node Exporter on instances
pub fn setup_node_exporter_cmd(node_exporter_version: &str) -> String {
    let node_exporter_url = format!(
      "https://github.com/prometheus/node_exporter/releases/download/v{}/node_exporter-{}.linux-arm64.tar.gz",
      node_exporter_version, node_exporter_version
  );
    format!(
        r#"
sudo apt-get update -y
sudo apt-get install -y wget tar

# Download Node Exporter with retries
for i in {{1..5}}; do
  wget -O /home/ubuntu/node_exporter.tar.gz {} && break
  sleep 10
done

# Install Node Exporter
sudo mkdir -p /opt/node_exporter
tar xvfz /home/ubuntu/node_exporter.tar.gz -C /home/ubuntu
sudo mv /home/ubuntu/node_exporter-{}.linux-arm64 /opt/node_exporter/node_exporter-{}.linux-arm64
sudo ln -s /opt/node_exporter/node_exporter-{}.linux-arm64/node_exporter /opt/node_exporter/node_exporter
sudo chmod +x /opt/node_exporter/node_exporter
sudo mv /home/ubuntu/node_exporter.service /etc/systemd/system/node_exporter.service

# Start service
sudo systemctl daemon-reload
sudo systemctl start node_exporter
sudo systemctl enable node_exporter
"#,
        node_exporter_url, node_exporter_version, node_exporter_version, node_exporter_version
    )
}

/// Systemd service file content for Node Exporter
pub const NODE_EXPORTER_SERVICE: &str = r#"
[Unit]
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
pub fn generate_prometheus_config(instances: &[(&str, &str, &str)]) -> String {
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
    for (name, ip, region) in instances {
        config.push_str(&format!(
            r#"
  - job_name: '{}_binary'
    static_configs:
      - targets: ['{}:9090']
        labels:
          deployer_name: '{}'
          deployer_ip: '{}'
          deployer_region: '{}'
  - job_name: '{}_system'
    static_configs:
      - targets: ['{}:9100']
        labels:
          deployer_name: '{}'
          deployer_ip: '{}'
          deployer_region: '{}'
  - job_name: '{}_memleak'
    static_configs:
      - targets: ['{}:9200']
        labels:
          deployer_name: '{}'
          deployer_ip: '{}'
          deployer_region: '{}'
"#,
            name, ip, name, ip, region, name, ip, name, ip, region, name, ip, name, ip, region
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
ExecStart=/home/ubuntu/binary --hosts=/home/ubuntu/hosts.yaml --config=/home/ubuntu/config.conf
TimeoutStopSec=60
Restart=always
User=ubuntu
LimitNOFILE=infinity
StandardOutput=append:/var/log/binary.log
StandardError=append:/var/log/binary.log

[Install]
WantedBy=multi-user.target
"#;

/// Shell script content for the Pyroscope agent (perf + wget)
pub fn generate_pyroscope_script(
    monitoring_private_ip: &str,
    name: &str,
    ip: &str,
    region: &str,
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
RAW_APP_NAME="binary{{deployer_name={name},deployer_ip={ip},deployer_region={region}}}"
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
pub const PYROSCOPE_AGENT_SERVICE: &str = r#"
[Unit]
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
pub const PYROSCOPE_AGENT_TIMER: &str = r#"
[Unit]
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

/// Expose memory usage via Prometheus metrics
pub const MEMLEAK_AGENT_SCRIPT: &str = r#"#!/bin/bash
set -e

SERVICE_NAME="binary.service"
METRICS_PORT=9200
METRICS_PATH="/metrics"
FIFO_PATH="/tmp/memleak_fifo"
METRICS_FILE="/tmp/memleak_metrics"
LEAK_THRESHOLD=1024 # bytes, minimum leak size to report (1KB)
MEMLEAK_REPORT_INTERVAL=60 # seconds between leak reports

# Ensure we have a clean environment
cleanup() {
  echo "Cleaning up..."
  # Kill the HTTP server if running
  if [ -n "$HTTP_PID" ]; then
    kill $HTTP_PID 2>/dev/null || true
  fi
  # Kill memleak if running
  if [ -n "$MEMLEAK_PID" ]; then
    sudo kill $MEMLEAK_PID 2>/dev/null || true
  fi
  # Kill parser if running
  if [ -n "$PARSER_PID" ]; then
    kill $PARSER_PID 2>/dev/null || true
  fi
  # Remove temporary files
  rm -f "$METRICS_FILE"
  rm -f "$FIFO_PATH"
  exit 0
}

trap cleanup SIGINT SIGTERM EXIT

# Create a named pipe for memleak output
[ -p "$FIFO_PATH" ] || mkfifo "$FIFO_PATH"

# Start a simple HTTP server to expose metrics
start_http_server() {
  echo "Starting HTTP server on port $METRICS_PORT..."
  # Use netcat to create a simple HTTP server
  while true; do
    echo -e "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n$(cat $METRICS_FILE)" | nc -l -p $METRICS_PORT -q 1
  done
}

# Initialize metrics file with metadata
init_metrics() {
  cat > "$METRICS_FILE" << EOF
# HELP inuse_bytes Memory allocated on the heap
# TYPE inuse_bytes gauge
# HELP inuse_objects Number of objects allocated on the heap
# TYPE inuse_objects gauge
EOF
}

# Start memleak in continuous mode with output to a named pipe
start_memleak() {
  local pid=$1

  echo "Starting continuous memleak monitoring for PID $pid..."

  # Start memleak in background with continuous monitoring
  sudo memleak-bpfcc -z $LEAK_THRESHOLD -p $pid $MEMLEAK_REPORT_INTERVAL > "$FIFO_PATH" 2>/dev/null &
  MEMLEAK_PID=$!
  echo "Memleak started with PID $MEMLEAK_PID"
}

# Start the output parser
start_parser() {
  echo "Starting parser process to watch memleak output..."

  # This function runs as a separate process to read from the FIFO
  # and update metrics whenever a new complete report is available
  (
    # Variables to track parsing state
    CURRENT_SNAPSHOT=""
    IN_SNAPSHOT=0

    # Read the FIFO line by line
    while IFS= read -r line; do
      # Look for timestamp marker that indicates the start of a new report
      if [[ "$line" =~ \[([0-9]{2}:[0-9]{2}:[0-9]{2})\] ]]; then
        # If we were already in a snapshot, this means we've finished one
        # and are starting a new one, so process the completed snapshot
        if [ $IN_SNAPSHOT -eq 1 ] && [ -n "$CURRENT_SNAPSHOT" ]; then
          process_snapshot "$CURRENT_SNAPSHOT"
        fi

        # Start a new snapshot
        CURRENT_SNAPSHOT="$line"
        IN_SNAPSHOT=1
      elif [ $IN_SNAPSHOT -eq 1 ]; then
        # Add line to current snapshot
        CURRENT_SNAPSHOT="$CURRENT_SNAPSHOT
  $line"
      fi
    done < "$FIFO_PATH"
  ) &
  PARSER_PID=$!
  echo "Parser started with PID $PARSER_PID"
}

# Process a complete memleak snapshot and update metrics
process_snapshot() {
  local snapshot="$1"

  # Use awk to parse the snapshot and extract metrics
  awk '
  BEGIN {
    in_leak_section = 0;
  }

  /Top [0-9]+ stacks with outstanding allocations/ { in_leak_section = 1; next; }

  /^\s*([0-9]+) bytes in ([0-9]+) allocations.*/ {
    if (!in_leak_section) next;

    bytes = $1;
    objects = $4;

    # Extract stack trace and clean it up
    stack = "";
    getline; # Move to first stack frame line
    while ($0 ~ /^\s+\S+/) {
      frame = $0;
      gsub(/\+0x[0-9a-f]+ \[[^\]]+\]/, "", frame);
      gsub(/^\s+/, "", frame);
      # Replace spaces and special chars with underscores
      gsub(/[^a-zA-Z0-9_]/, "_", frame);

      if (stack == "") {
        stack = frame;
      } else {
        stack = stack ";" frame;
      }

      if (getline <= 0) break;
    }

    # Create metric with stack as label
    if (stack != "") {
      printf("inuse_bytes{stack=\"%s\"} %d\n", stack, bytes);
      printf("inuse_objects{stack=\"%s\"} %d\n", stack, objects);
    }
  }
  ' <<< "$snapshot" > "$METRICS_FILE.new"

  # Add metadata back to the beginning of the file
  init_metrics > "$METRICS_FILE.tmp"
  cat "$METRICS_FILE.new" >> "$METRICS_FILE.tmp"
  mv "$METRICS_FILE.tmp" "$METRICS_FILE"
  rm -f "$METRICS_FILE.new"

  # Log that we've processed a new snapshot
  echo "Processed new memleak snapshot at $(date)"
}

# Function to check if memleak is still running
check_memleak() {
  if [ -n "$MEMLEAK_PID" ] && ! ps -p $MEMLEAK_PID > /dev/null; then
    echo "Memleak process $MEMLEAK_PID is no longer running. Restarting..." >&2
    MEMLEAK_PID=""
    return 1
  fi
  return 0
}

# Function to check if parser is still running
check_parser() {
  if [ -n "$PARSER_PID" ] && ! ps -p $PARSER_PID > /dev/null; then
    echo "Parser process $PARSER_PID is no longer running. Restarting..." >&2
    PARSER_PID=""
    return 1
  fi
  return 0
}

# Function to check if binary is still running
check_binary() {
  if ! ps -p $BINARY_PID > /dev/null; then
    echo "Binary process $BINARY_PID is no longer running. Getting new PID..." >&2
    BINARY_PID=$(systemctl show --property MainPID ${SERVICE_NAME} | cut -d= -f2)
    if [ -z "$BINARY_PID" ] || [ "$BINARY_PID" -eq 0 ]; then
      echo "Error: Could not get PID for ${SERVICE_NAME}. Waiting..." >&2
      return 1
    fi
    echo "New binary PID: $BINARY_PID" >&2
    # If binary changed, restart memleak
    if [ -n "$MEMLEAK_PID" ]; then
      sudo kill $MEMLEAK_PID 2>/dev/null || true
      MEMLEAK_PID=""
    fi
    return 1
  fi
  return 0
}

# Main execution
echo "Starting continuous memory leak monitoring on port $METRICS_PORT..."

# Initialize metrics file
init_metrics

# Start HTTP server in background
start_http_server &
HTTP_PID=$!
echo "HTTP server started with PID $HTTP_PID"

# Get the PID of the binary service
BINARY_PID=$(systemctl show --property MainPID ${SERVICE_NAME} | cut -d= -f2)
if [ -z "$BINARY_PID" ] || [ "$BINARY_PID" -eq 0 ]; then
  echo "Error: Could not get PID for ${SERVICE_NAME}. Waiting for service to start..." >&2

  # Wait for service to start, checking every 10 seconds
  while true; do
    BINARY_PID=$(systemctl show --property MainPID ${SERVICE_NAME} | cut -d= -f2)
    if [ -n "$BINARY_PID" ] && [ "$BINARY_PID" -ne 0 ]; then
      echo "Service started with PID $BINARY_PID"
      break
    fi
    sleep 10
  done
fi

# Start the parser process
start_parser

# Start memleak with the binary PID
start_memleak $BINARY_PID

# Main monitoring loop - check status and restart processes if needed
echo "Continuous monitoring active. Checking process health every 30 seconds..."
while true; do
  # Check binary status
  check_binary || {
    # If binary PID changed, restart memleak
    if [ -n "$BINARY_PID" ]; then
      start_memleak $BINARY_PID
    fi
  }

  # Make sure memleak is running
  check_memleak || {
    if [ -n "$BINARY_PID" ]; then
      start_memleak $BINARY_PID
    fi
  }

  # Make sure parser is running
  check_parser || start_parser

  # Wait before next check
  sleep 30
done
"#;

/// Systemd service file content for the Memleak agent script
pub const MEMLEAK_AGENT_SERVICE: &str = r#"
[Unit]
Description=Memleak Agent (BCC Script Runner)
Wants=network-online.target
After=network-online.target binary.service

[Service]
ExecStart=/home/ubuntu/memleak-agent.sh
TimeoutStopSec=60
Restart=always
User=ubuntu
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
"#;
