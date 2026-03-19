use super::sniffer::TraceEntry;
use serde::{Deserialize, Serialize};

/// Serializable trace document for quint test generation.
#[derive(Serialize, Deserialize)]
pub struct TraceData {
    pub n: usize,
    pub faults: usize,
    pub epoch: u64,
    pub max_view: u64,
    pub entries: Vec<TraceEntry>,
    pub required_containers: u64,
}
