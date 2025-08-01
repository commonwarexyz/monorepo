use aws_config::{BehaviorVersion, Region, SdkConfig};
use aws_sdk_ec2::Client as Ec2Client;
use std::path::PathBuf;
use testcontainers::{clients, core::WaitFor, ContainerAsync, GenericImage};

pub const LOCALSTACK_IMAGE: &str = "localstack/localstack";
pub const LOCALSTACK_VERSION: &str = "latest";

pub struct LocalStackContainer {
    container: ContainerAsync<GenericImage>,
    endpoint: String,
}

impl LocalStackContainer {
    pub async fn new() -> Self {
        let docker = clients::Cli::default();
        
        let container = docker.run(
            GenericImage::new(LOCALSTACK_IMAGE, LOCALSTACK_VERSION)
                .with_exposed_port(4566)
                .with_env_var("SERVICES", "ec2,ssm,sts,iam")
                .with_env_var("DEBUG", "1")
                .with_env_var("AWS_DEFAULT_REGION", "us-east-1")
                .with_env_var("PERSISTENCE", "1")
                .with_wait_for(WaitFor::message_on_stdout("Ready.")),
        );

        let host_port = container.get_host_port_ipv4(4566);
        let endpoint = format!("http://localhost:{}", host_port);

        // Set environment variables for AWS SDK
        std::env::set_var("AWS_ACCESS_KEY_ID", "test");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "test");
        std::env::set_var("AWS_ENDPOINT_URL", &endpoint);

        Self { container, endpoint }
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub async fn sdk_config(&self, region: &str) -> SdkConfig {
        aws_config::defaults(BehaviorVersion::latest())
            .region(Region::new(region))
            .endpoint_url(&self.endpoint)
            .credentials_provider(aws_config::credentials::Credentials::new(
                "test",
                "test",
                None,
                None,
                "static",
            ))
            .load()
            .await
    }

    pub async fn ec2_client(&self, region: &str) -> Ec2Client {
        let config = self.sdk_config(region).await;
        Ec2Client::new(&config)
    }
}

pub struct TestFiles {
    pub dir: PathBuf,
    pub binary: PathBuf,
    pub config: PathBuf,
    pub dashboard: PathBuf,
}

impl TestFiles {
    pub fn create(test_name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("deployer_test_{}", test_name));
        std::fs::create_dir_all(&dir).unwrap();

        let binary = dir.join("test-binary");
        let config = dir.join("test-config.conf");
        let dashboard = dir.join("dashboard.json");

        // Create test binary
        let test_binary_content = r#"#!/bin/bash
echo "Test binary running on port 9090"
while true; do
    echo "Metrics" | nc -l 9090 || true
    sleep 1
done
"#;
        std::fs::write(&binary, test_binary_content).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        // Create test config
        let test_config = r#"# Test configuration
port = 8080
log_level = "info"
metrics_port = 9090
"#;
        std::fs::write(&config, test_config).unwrap();

        // Create test dashboard
        let test_dashboard = r#"{
  "annotations": {
    "list": [
      {
        "builtIn": 1,
        "datasource": {
          "type": "grafana",
          "uid": "-- Grafana --"
        },
        "enable": true,
        "hide": true,
        "iconColor": "rgba(0, 211, 255, 1)",
        "name": "Annotations & Alerts",
        "type": "dashboard"
      }
    ]
  },
  "editable": true,
  "fiscalYearStartMonth": 0,
  "graphTooltip": 0,
  "id": null,
  "links": [],
  "liveNow": false,
  "panels": [],
  "refresh": "",
  "schemaVersion": 39,
  "tags": ["test"],
  "templating": {
    "list": []
  },
  "time": {
    "from": "now-6h",
    "to": "now"
  },
  "timepicker": {},
  "timezone": "browser",
  "title": "Test Dashboard",
  "uid": null,
  "version": 0,
  "weekStart": ""
}"#;
        std::fs::write(&dashboard, test_dashboard).unwrap();

        Self {
            dir,
            binary,
            config,
            dashboard,
        }
    }
}

impl Drop for TestFiles {
    fn drop(&mut self) {
        if self.dir.exists() {
            std::fs::remove_dir_all(&self.dir).ok();
        }
    }
}

pub fn cleanup_deployer_dir(tag: &str) {
    if let Ok(home) = std::env::var("HOME") {
        let deployer_dir = PathBuf::from(home)
            .join(".commonware_deployer")
            .join(tag);
        
        if deployer_dir.exists() {
            std::fs::remove_dir_all(&deployer_dir).ok();
        }
    }
}

#[macro_export]
macro_rules! assert_aws_error {
    ($result:expr, $error_type:ty) => {
        match $result {
            Err(e) => {
                assert!(e.downcast_ref::<$error_type>().is_some(), 
                    "Expected error type {}, but got: {:?}", 
                    stringify!($error_type), 
                    e
                );
            }
            Ok(_) => panic!("Expected error, but operation succeeded"),
        }
    };
}