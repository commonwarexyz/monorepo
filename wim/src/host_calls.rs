//! Host Call Handler for PolkaVM Trace Extraction
//!
//! Provides infrastructure for handling external calls (ecalli) during
//! PolkaVM execution tracing. The host handler is responsible for:
//!
//! 1. Executing the actual host function (network I/O, etc.)
//! 2. Recording inputs/outputs for the trace
//! 3. Returning results to the guest program
//!
//! This design separates the tracing infrastructure from specific host
//! implementations (IBP probe, generic RPC, etc.)

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// Record of a single host call for inclusion in the trace
#[derive(Debug, Clone)]
pub struct HostCallRecord {
    /// Host call ID (ecalli number)
    pub call_id: u32,
    /// Input arguments (register values or memory data)
    pub inputs: Vec<Vec<u8>>,
    /// Output/return value
    pub output: Vec<u8>,
    /// Timestamp when call was made (ms since epoch)
    pub timestamp_ms: u64,
}

/// Complete trace of all host calls during execution
#[derive(Debug, Clone, Default)]
pub struct HostCallTrace {
    /// All host calls in execution order
    pub calls: Vec<HostCallRecord>,
    /// Hash of the guest program
    pub program_hash: [u8; 32],
    /// Execution start time
    pub start_time_ms: u64,
    /// Execution end time
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

    pub fn record(&mut self, call: HostCallRecord) {
        self.calls.push(call);
    }

    pub fn finalize(&mut self) {
        #[cfg(feature = "std")]
        {
            self.end_time_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64;
        }
    }

    /// Compute commitment to the trace for proof generation
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

/// Trait for handling host calls during PolkaVM execution
///
/// Implementors provide the actual host function logic (network I/O, etc.)
/// while the tracer records inputs/outputs for proof generation.
pub trait HostCallHandler: Send + Sync {
    /// Handle a host call from the guest
    ///
    /// # Arguments
    /// - `call_id`: The ecalli number (host function ID)
    /// - `memory`: Guest memory (for reading inputs/writing outputs)
    /// - `a0..a5`: Register arguments passed by guest
    ///
    /// # Returns
    /// - `(result, trace_record)`: Return value for A0 and trace record
    fn handle_call(
        &self,
        call_id: u32,
        memory: &mut [u8],
        a0: u32,
        a1: u32,
        a2: u32,
        a3: u32,
        a4: u32,
        a5: u32,
    ) -> (u32, Option<HostCallRecord>);

    /// Get the accumulated trace
    fn get_trace(&self) -> HostCallTrace;

    /// Reset the handler for a new execution
    fn reset(&self);
}

/// Dummy host handler that returns constants (for testing)
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
        &self,
        call_id: u32,
        _memory: &mut [u8],
        a0: u32,
        a1: u32,
        _a2: u32,
        _a3: u32,
        _a4: u32,
        _a5: u32,
    ) -> (u32, Option<HostCallRecord>) {
        // Return dummy value
        let result: u32 = match call_id {
            0x100..=0x10F => 50,   // TCP/ping - 50ms latency
            0x110..=0x11F => 200,  // HTTP - 200 status
            0x120..=0x12F => 1,    // WSS - handle 1
            0x130..=0x13F => 1,    // RPC - success
            0x160 => 1000,         // Timestamp low
            _ => 100,              // Default
        };

        let record = HostCallRecord {
            call_id,
            inputs: vec![
                a0.to_le_bytes().to_vec(),
                a1.to_le_bytes().to_vec(),
            ],
            output: result.to_le_bytes().to_vec(),
            #[cfg(feature = "std")]
            timestamp_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
            #[cfg(not(feature = "std"))]
            timestamp_ms: 0,
        };

        #[cfg(feature = "std")]
        self.trace.lock().unwrap().record(record.clone());

        (result, Some(record))
    }

    fn get_trace(&self) -> HostCallTrace {
        #[cfg(feature = "std")]
        {
            self.trace.lock().unwrap().clone()
        }
        #[cfg(not(feature = "std"))]
        {
            HostCallTrace::new()
        }
    }

    fn reset(&self) {
        #[cfg(feature = "std")]
        {
            *self.trace.lock().unwrap() = HostCallTrace::new();
        }
    }
}

/// Host call IDs for IBP monitoring probe
/// These must match the guest program constants
pub mod ibp_calls {
    // Network primitives
    pub const TCP_PING: u32 = 0x100;
    pub const WSS_CONNECT: u32 = 0x101;
    pub const WSS_SUBSCRIBE: u32 = 0x102;
    pub const RPC_CALL: u32 = 0x103;
    pub const RELAY_FINALIZED: u32 = 0x104;
    pub const TIMESTAMP: u32 = 0x105;
    pub const READ_INPUT: u32 = 0x106;
    pub const WRITE_OUTPUT: u32 = 0x107;

    // Extended network primitives
    pub const DNS_RESOLVE: u32 = 0x103;
    pub const HTTP_GET: u32 = 0x110;
    pub const HTTP_POST: u32 = 0x111;

    // Substrate-specific
    pub const SUBSTRATE_CHAIN_HEAD: u32 = 0x140;
    pub const SUBSTRATE_SYSTEM_HEALTH: u32 = 0x142;
    pub const SUBSTRATE_SYNC_STATE: u32 = 0x145;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dummy_handler() {
        let handler = DummyHostHandler::new();
        let mut memory = [0u8; 1024];

        let (result, record) = handler.handle_call(
            ibp_calls::TCP_PING,
            &mut memory,
            0, 0, 0, 0, 0, 0,
        );

        assert_eq!(result, 50); // dummy latency
        assert!(record.is_some());
        assert_eq!(record.unwrap().call_id, ibp_calls::TCP_PING);
    }

    #[test]
    fn test_trace_commitment() {
        let mut trace = HostCallTrace::new();
        trace.program_hash = [1; 32];
        trace.record(HostCallRecord {
            call_id: 0x100,
            inputs: vec![vec![1, 2, 3]],
            output: vec![50, 0, 0, 0],
            timestamp_ms: 1000,
        });

        let commitment = trace.commitment();
        assert_ne!(commitment, [0; 32]);

        // Commitment should be deterministic
        let commitment2 = trace.commitment();
        assert_eq!(commitment, commitment2);
    }
}
