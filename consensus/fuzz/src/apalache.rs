//! Apalache JSON-RPC client for interactive symbolic testing.
//!
//! Communicates with an Apalache server running in explorer mode via
//! JSON-RPC over HTTP. The server is started separately:
//!
//! ```bash
//! docker run --rm -p 8822:8822 \
//!   ghcr.io/apalache-mc/apalache:latest server --server-type=explorer
//! ```

use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};

/// Errors from Apalache JSON-RPC calls.
#[derive(Debug)]
pub enum Error {
    /// HTTP transport error.
    Http(reqwest::Error),
    /// JSON-RPC error response.
    Rpc { code: i64, message: String },
    /// Missing expected field in response.
    MissingField(&'static str),
    /// Transition is disabled.
    Disabled,
    /// Solver returned UNKNOWN status.
    Unknown,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Http(e) => write!(f, "HTTP error: {e}"),
            Error::Rpc { code, message } => write!(f, "RPC error {code}: {message}"),
            Error::MissingField(field) => write!(f, "missing field: {field}"),
            Error::Disabled => write!(f, "transition disabled"),
            Error::Unknown => write!(f, "solver returned UNKNOWN"),
        }
    }
}

impl std::error::Error for Error {}

impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        Error::Http(e)
    }
}

/// Session returned by `load_spec`.
pub struct Session {
    pub id: String,
    pub snapshot_id: u64,
    pub init_transitions: Vec<Transition>,
    pub next_transitions: Vec<Transition>,
}

/// A transition descriptor from `specParameters`.
#[derive(Debug, Clone)]
pub struct Transition {
    pub index: u64,
    pub labels: Vec<String>,
}

/// Result of `assume_transition`.
pub struct AssumeResult {
    pub snapshot_id: u64,
    pub status: TransitionStatus,
}

/// Status of a transition check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionStatus {
    Enabled,
    Disabled,
    Unknown,
}

/// Result of `next_state`.
pub struct NextStateResult {
    pub snapshot_id: u64,
    pub step_no: u64,
}

/// Result of `query`.
pub struct QueryResult {
    pub trace: Option<Value>,
    pub state: Option<Value>,
    pub operator_value: Option<Value>,
}

/// Blocking JSON-RPC client for the Apalache explorer server.
pub struct ApalacheClient {
    client: reqwest::blocking::Client,
    url: String,
    next_id: AtomicU64,
}

impl ApalacheClient {
    /// Creates a client connecting to the given URL (e.g. `http://localhost:8822/rpc`).
    pub fn new(url: &str) -> Self {
        Self {
            client: reqwest::blocking::Client::new(),
            url: url.to_string(),
            next_id: AtomicU64::new(1),
        }
    }

    /// Calls a JSON-RPC method and returns the `result` field.
    fn call(&self, method: &str, params: Value) -> Result<Value, Error> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let body = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": id,
        });

        let resp: Value = self
            .client
            .post(&self.url)
            .header("Content-Type", "application/json")
            .json(&body)
            .send()?
            .json()?;

        if let Some(err) = resp.get("error") {
            let code = err["code"].as_i64().unwrap_or(-1);
            let message = err["message"].as_str().unwrap_or("unknown").to_string();
            return Err(Error::Rpc { code, message });
        }

        resp.get("result")
            .cloned()
            .ok_or(Error::MissingField("result"))
    }

    /// Checks server health.
    pub fn health(&self) -> Result<(), Error> {
        let result = self.call("health", json!({}))?;
        let status = result["status"].as_str().unwrap_or("");
        if status == "OK" {
            Ok(())
        } else {
            Err(Error::MissingField("status"))
        }
    }

    /// Loads a TLA+ specification from base64-encoded sources.
    pub fn load_spec(
        &self,
        sources_base64: &[String],
        init: Option<&str>,
        next: Option<&str>,
        invariants: &[&str],
    ) -> Result<Session, Error> {
        let mut params = json!({
            "sources": sources_base64,
            "invariants": invariants,
        });
        if let Some(init) = init {
            params["init"] = json!(init);
        }
        if let Some(next) = next {
            params["next"] = json!(next);
        }

        let result = self.call("loadSpec", params)?;

        let session_id = result["sessionId"]
            .as_str()
            .ok_or(Error::MissingField("sessionId"))?
            .to_string();
        let snapshot_id = result["snapshotId"].as_u64().unwrap_or(0);

        let spec_params = &result["specParameters"];
        let init_transitions = parse_transitions(&spec_params["initTransitions"]);
        let next_transitions = parse_transitions(&spec_params["nextTransitions"]);

        Ok(Session {
            id: session_id,
            snapshot_id,
            init_transitions,
            next_transitions,
        })
    }

    /// Disposes of a session, releasing server resources.
    pub fn dispose_spec(&self, session_id: &str) -> Result<(), Error> {
        self.call("disposeSpec", json!({ "sessionId": session_id }))?;
        Ok(())
    }

    /// Rolls back to a previous snapshot.
    pub fn rollback(&self, session_id: &str, snapshot_id: u64) -> Result<u64, Error> {
        let result = self.call(
            "rollback",
            json!({
                "sessionId": session_id,
                "snapshotId": snapshot_id,
            }),
        )?;
        Ok(result["snapshotId"].as_u64().unwrap_or(snapshot_id))
    }

    /// Assumes a transition (prepares it in the SMT context).
    pub fn assume_transition(
        &self,
        session_id: &str,
        transition_id: u64,
        check_enabled: bool,
    ) -> Result<AssumeResult, Error> {
        let result = self.call(
            "assumeTransition",
            json!({
                "sessionId": session_id,
                "transitionId": transition_id,
                "checkEnabled": check_enabled,
            }),
        )?;

        let snapshot_id = result["snapshotId"].as_u64().unwrap_or(0);
        let status = match result["status"].as_str().unwrap_or("UNKNOWN") {
            "ENABLED" => TransitionStatus::Enabled,
            "DISABLED" => TransitionStatus::Disabled,
            _ => TransitionStatus::Unknown,
        };

        Ok(AssumeResult {
            snapshot_id,
            status,
        })
    }

    /// Advances to the next symbolic state.
    pub fn next_step(&self, session_id: &str) -> Result<NextStateResult, Error> {
        let result = self.call("nextStep", json!({ "sessionId": session_id }))?;

        Ok(NextStateResult {
            snapshot_id: result["snapshotId"].as_u64().unwrap_or(0),
            step_no: result["newStepNo"].as_u64().unwrap_or(0),
        })
    }

    /// Queries state, trace, or operator values.
    pub fn query(
        &self,
        session_id: &str,
        kinds: &[&str],
        operator: Option<&str>,
    ) -> Result<QueryResult, Error> {
        let mut params = json!({
            "sessionId": session_id,
            "kinds": kinds,
        });
        if let Some(op) = operator {
            params["operator"] = json!(op);
        }

        let result = self.call("query", params)?;

        Ok(QueryResult {
            trace: result.get("trace").filter(|v| !v.is_null()).cloned(),
            state: result.get("state").filter(|v| !v.is_null()).cloned(),
            operator_value: result
                .get("operatorValue")
                .filter(|v| !v.is_null())
                .cloned(),
        })
    }

    /// Constrains state variables to specific values.
    pub fn assume_state(
        &self,
        session_id: &str,
        equalities: &Value,
        check_enabled: bool,
    ) -> Result<AssumeResult, Error> {
        let result = self.call(
            "assumeState",
            json!({
                "sessionId": session_id,
                "checkEnabled": check_enabled,
                "equalities": equalities,
            }),
        )?;

        let snapshot_id = result["snapshotId"].as_u64().unwrap_or(0);
        let status = match result["status"].as_str().unwrap_or("UNKNOWN") {
            "ENABLED" => TransitionStatus::Enabled,
            "DISABLED" => TransitionStatus::Disabled,
            _ => TransitionStatus::Unknown,
        };

        Ok(AssumeResult {
            snapshot_id,
            status,
        })
    }

    /// Compacts the solver state by concretizing the symbolic trace.
    pub fn compact(&self, session_id: &str, snapshot_id: u64) -> Result<u64, Error> {
        let result = self.call(
            "compact",
            json!({
                "sessionId": session_id,
                "snapshotId": snapshot_id,
            }),
        )?;
        Ok(result["snapshotId"].as_u64().unwrap_or(0))
    }

    /// Checks an invariant against the current symbolic path.
    pub fn check_invariant(
        &self,
        session_id: &str,
        invariant_id: u64,
        kind: &str,
    ) -> Result<(String, Option<Value>), Error> {
        let result = self.call(
            "checkInvariant",
            json!({
                "sessionId": session_id,
                "invariantId": invariant_id,
                "kind": kind,
            }),
        )?;

        let status = result["invariantStatus"]
            .as_str()
            .unwrap_or("UNKNOWN")
            .to_string();
        let trace = result.get("trace").filter(|v| !v.is_null()).cloned();

        Ok((status, trace))
    }
}

fn parse_transitions(v: &Value) -> Vec<Transition> {
    let Some(arr) = v.as_array() else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|t| {
            let index = t["index"].as_u64()?;
            let labels = t["labels"]
                .as_array()?
                .iter()
                .filter_map(|l| l.as_str().map(String::from))
                .collect();
            Some(Transition { index, labels })
        })
        .collect()
}
