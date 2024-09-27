use prometheus_client::{
    encoding::EncodeLabelSet,
    metrics::{counter::Counter, family::Family},
    registry::Registry,
};
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
};

#[derive(Debug)]
pub struct Metrics {
    tasks_spawned: Counter,
    task_polls: Counter,
    bandwidth: Family<Link, Counter>,
}

impl Metrics {
    pub fn init(registry: Arc<Mutex<Registry>>) -> Self {
        let metrics = Self {
            bandwidth: Family::default(),
            task_polls: Counter::default(),
            tasks_spawned: Counter::default(),
        };
        {
            let mut registry = registry.lock().unwrap();
            registry.register(
                "tasks_spawned",
                "Total number of tasks spawned",
                metrics.tasks_spawned.clone(),
            );
            registry.register(
                "task_polls",
                "Total number of task polls",
                metrics.task_polls.clone(),
            );
            registry.register(
                "bandwidth",
                "Bandwidth usage by origin and destination",
                metrics.bandwidth.clone(),
            );
        }
        metrics
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct Link {
    origin: String,
    destination: String,
}

impl Metrics {
    pub fn record_task_spawned(&self) {
        self.tasks_spawned.inc();
    }

    pub fn record_task_poll(&self) {
        self.task_polls.inc();
    }

    pub fn record_bandwidth(&self, origin: SocketAddr, destination: SocketAddr, bytes: usize) {
        let link = Link {
            origin: origin.to_string(),
            destination: destination.to_string(),
        };
        self.bandwidth.get_or_create(&link).inc_by(bytes as u64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{net::IpAddr, net::Ipv4Addr, net::SocketAddr};

    #[test]
    fn test_bandwidth_metrics() {
        let registry = Arc::new(Mutex::new(Registry::default()));
        let metrics = Metrics::init(registry.clone());

        // Send some data
        let socket1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080);
        let socket2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8081);
        metrics.record_bandwidth(socket1, socket2, 100);
        metrics.record_bandwidth(socket2, socket1, 200);
        metrics.record_bandwidth(socket2, socket1, 150);

        // Verify tracking
        assert_eq!(
            metrics
                .bandwidth
                .get_or_create(&Link {
                    origin: socket1.to_string(),
                    destination: socket2.to_string(),
                })
                .get(),
            100
        );
        assert_eq!(
            metrics
                .bandwidth
                .get_or_create(&Link {
                    origin: socket2.to_string(),
                    destination: socket1.to_string(),
                })
                .get(),
            350
        );
    }

    #[test]
    fn test_task_metrics() {
        let registry = Arc::new(Mutex::new(Registry::default()));
        let metrics = Metrics::init(registry.clone());

        for _ in 0..5 {
            metrics.record_task_spawned();
        }

        for _ in 0..10 {
            metrics.record_task_poll();
        }

        assert_eq!(metrics.tasks_spawned.get(), 5);
        assert_eq!(metrics.task_polls.get(), 10);
    }
}
