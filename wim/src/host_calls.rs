//! Host Call Handler for PolkaVM Trace Extraction

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[derive(Debug, Clone)]
pub struct HostCallRecord {
    pub call_id: u32,
    pub inputs: Vec<Vec<u8>>,
    pub output: Vec<u8>,
    pub timestamp_ms: u64,
}

#[derive(Debug, Clone, Default)]
pub struct HostCallTrace {
    pub calls: Vec<HostCallRecord>,
    pub program_hash: [u8; 32],
    pub start_time_ms: u64,
    pub end_time_ms: u64,
}

impl HostCallTrace {
    pub fn new() -> Self {
        Self {
            calls: Vec::new(),
            program_hash: [0; 32],
            #[cfg(feature = "std")]
            start_time_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
            #[cfg(not(feature = "std"))]
            start_time_ms: 0,
            end_time_ms: 0,
        }
    }

    pub fn record(&mut self, call: HostCallRecord) { self.calls.push(call); }

    pub fn finalize(&mut self) {
        #[cfg(feature = "std")]
        {
            self.end_time_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64;
        }
    }

    pub fn commitment(&self) -> [u8; 32] {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(&self.program_hash);
        hasher.update(&self.start_time_ms.to_le_bytes());
        for call in &self.calls {
            hasher.update(&call.call_id.to_le_bytes());
            for input in &call.inputs {
                hasher.update(&(input.len() as u32).to_le_bytes());
                hasher.update(input);
            }
            hasher.update(&(call.output.len() as u32).to_le_bytes());
            hasher.update(&call.output);
        }
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
}

pub trait HostCallHandler: Send + Sync {
    fn handle_call(
        &self, call_id: u32, memory: &mut [u8],
        a0: u32, a1: u32, a2: u32, a3: u32, a4: u32, a5: u32,
    ) -> (u32, Option<HostCallRecord>);
    fn get_trace(&self) -> HostCallTrace;
    fn reset(&self);
}

#[derive(Debug, Default)]
pub struct DummyHostHandler {
    #[cfg(feature = "std")]
    trace: std::sync::Mutex<HostCallTrace>,
}

impl DummyHostHandler {
    pub fn new() -> Self {
        Self {
            #[cfg(feature = "std")]
            trace: std::sync::Mutex::new(HostCallTrace::new()),
        }
    }
}

impl HostCallHandler for DummyHostHandler {
    fn handle_call(
        &self, call_id: u32, _memory: &mut [u8],
        a0: u32, a1: u32, _a2: u32, _a3: u32, _a4: u32, _a5: u32,
    ) -> (u32, Option<HostCallRecord>) {
        let result: u32 = match call_id {
            0x100..=0x10F => 50,
            0x110..=0x11F => 200,
            0x120..=0x12F => 1,
            0x130..=0x13F => 1,
            0x160 => 1000,
            _ => 100,
        };
        let record = HostCallRecord {
            call_id,
            inputs: vec![a0.to_le_bytes().to_vec(), a1.to_le_bytes().to_vec()],
            output: result.to_le_bytes().to_vec(),
            #[cfg(feature = "std")]
            timestamp_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64,
            #[cfg(not(feature = "std"))]
            timestamp_ms: 0,
        };
        #[cfg(feature = "std")]
        self.trace.lock().unwrap().record(record.clone());
        (result, Some(record))
    }

    fn get_trace(&self) -> HostCallTrace {
        #[cfg(feature = "std")]
        { self.trace.lock().unwrap().clone() }
        #[cfg(not(feature = "std"))]
        { HostCallTrace::new() }
    }

    fn reset(&self) {
        #[cfg(feature = "std")]
        { *self.trace.lock().unwrap() = HostCallTrace::new(); }
    }
}

pub mod ibp_calls {
    pub const TCP_PING: u32 = 0x100;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dummy_handler() {
        let handler = DummyHostHandler::new();
        let mut memory = [0u8; 1024];
        let (result, record) = handler.handle_call(ibp_calls::TCP_PING, &mut memory, 0, 0, 0, 0, 0, 0);
        assert_eq!(result, 50);
        assert!(record.is_some());
    }

    #[test]
    fn test_trace_commitment() {
        let mut trace = HostCallTrace::new();
        trace.program_hash = [1; 32];
        trace.record(HostCallRecord {
            call_id: 0x100, inputs: vec![vec![1, 2, 3]],
            output: vec![50, 0, 0, 0], timestamp_ms: 1000,
        });
        let commitment = trace.commitment();
        assert_ne!(commitment, [0; 32]);
        assert_eq!(commitment, trace.commitment());
    }
}
