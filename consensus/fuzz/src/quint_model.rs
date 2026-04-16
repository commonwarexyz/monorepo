use crate::{
    replayer::compare::ExpectedState,
    tracing::{data::TraceData, decoder, encoder},
};
use sha1::{Digest, Sha1};
use std::{
    collections::HashMap,
    error::Error,
    fmt::{self, Display},
    fs,
    path::{Path, PathBuf},
    process::{self, Command},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone)]
pub struct ModelError {
    message: String,
}

impl ModelError {
    fn new(message: String) -> Self {
        Self { message }
    }
}

impl Display for ModelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for ModelError {}

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn quint_dir() -> PathBuf {
    manifest_dir().join("../quint")
}

fn temp_dir() -> PathBuf {
    quint_dir().join(".mbf_model_tmp")
}

fn unique_stem(label: &str, suffix: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(label.as_bytes());
    hasher.update(suffix.as_bytes());
    hasher.update(process::id().to_string().as_bytes());
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before epoch")
        .as_nanos()
        .to_string();
    hasher.update(now.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn normalized_model_trace(trace: &TraceData) -> TraceData {
    let mut model_trace = trace.clone();
    model_trace.required_containers = 0;
    model_trace.reporter_states.clear();
    model_trace.expected_state = None;
    model_trace
}

fn encoder_config(trace: &TraceData) -> encoder::EncoderConfig {
    encoder::EncoderConfig {
        n: trace.n,
        faults: trace.faults,
        epoch: trace.epoch,
        max_view: trace.max_view,
        required_containers: 0,
    }
}

fn run_quint_test_module(
    label: &str,
    suffix: &str,
    qnt_source: &str,
    itf_output: Option<&Path>,
) -> Result<(), ModelError> {
    let temp_dir = temp_dir();
    fs::create_dir_all(&temp_dir)
        .map_err(|e| ModelError::new(format!("failed to create {}: {e}", temp_dir.display())))?;

    let stem = unique_stem(label, suffix);
    let qnt_path = temp_dir.join(format!("{stem}.qnt"));

    fs::write(&qnt_path, qnt_source)
        .map_err(|e| ModelError::new(format!("failed to write {}: {e}", qnt_path.display())))?;

    let mut command = Command::new("quint");
    command
        .current_dir(quint_dir())
        .env("NODE_OPTIONS", "--max-old-space-size=8192")
        .args([
            "test",
            "--main=tests",
            "--backend=rust",
            "--max-samples=1",
            "--match=traceTest",
        ]);
    if let Some(itf_path) = itf_output {
        command.arg(format!(
            "--out-itf={}",
            itf_path.to_str().expect("utf8 itf path")
        ));
    }
    command.arg(qnt_path.to_str().expect("utf8 qnt path"));

    let output = command.output().map_err(|e| {
        ModelError::new(format!(
            "failed to run quint for {} [{}]: {e}",
            label,
            suffix,
        ))
    })?;

    let _ = fs::remove_file(&qnt_path);
    if let Some(itf) = itf_output {
        // ITF cleanup is handled by caller after reading the file
        if !output.status.success() {
            let _ = fs::remove_file(itf);
        }
    }
    let _ = fs::remove_dir(&temp_dir);

    if !output.status.success() {
        let mut message = format!(
            "quint test failed for {} [{}] (exit {})",
            label,
            suffix,
            output.status.code().unwrap_or(-1)
        );
        if !output.stdout.is_empty() {
            message.push_str("\n--- quint stdout ---\n");
            message.push_str(&String::from_utf8_lossy(&output.stdout));
        }
        if !output.stderr.is_empty() {
            message.push_str("\n--- quint stderr ---\n");
            message.push_str(&String::from_utf8_lossy(&output.stderr));
        }
        return Err(ModelError::new(message));
    }
    Ok(())
}

fn validate_replica_trace_with_itf(
    trace: &TraceData,
    label: &str,
    itf_path: &Path,
) -> Result<(), ModelError> {
    let cfg = encoder_config(trace);
    let qnt = encoder::encode(trace, &cfg);
    run_quint_test_module(label, "replica", &qnt, Some(itf_path))
}

/// Validates the trace against `replica.qnt` and extracts expected state
/// from the ITF output.
pub fn validate_and_extract_expected(
    trace: &TraceData,
    label: &str,
) -> Result<Option<ExpectedState>, ModelError> {
    let model_trace = normalized_model_trace(trace);

    // Validate against replica.qnt with ITF output
    let td = temp_dir();
    fs::create_dir_all(&td)
        .map_err(|e| ModelError::new(format!("failed to create {}: {e}", td.display())))?;
    let stem = unique_stem(label, "itf");
    let itf_path = td.join(format!("{stem}.itf.json"));

    validate_replica_trace_with_itf(&model_trace, label, &itf_path)?;

    // Parse the ITF file and extract expected state
    let expected = match fs::read_to_string(&itf_path) {
        Ok(itf_json) => {
            let _ = fs::remove_file(&itf_path);
            let _ = fs::remove_dir(&td);
            parse_itf_expected_state(&itf_json, trace)?
        }
        Err(e) => {
            let _ = fs::remove_file(&itf_path);
            let _ = fs::remove_dir(&td);
            return Err(ModelError::new(format!(
                "failed to read ITF output for {label}: {e}"
            )));
        }
    };

    Ok(Some(expected))
}

fn parse_itf_expected_state(
    itf_json: &str,
    trace: &TraceData,
) -> Result<ExpectedState, ModelError> {
    let itf: serde_json::Value = serde_json::from_str(itf_json)
        .map_err(|e| ModelError::new(format!("failed to parse ITF JSON: {e}")))?;

    let states = itf["states"]
        .as_array()
        .ok_or_else(|| ModelError::new("ITF JSON missing 'states' array".to_string()))?;

    let final_state = states
        .last()
        .ok_or_else(|| ModelError::new("ITF 'states' array is empty".to_string()))?;

    // Build block map: invert encoder::build_block_map to get name -> hex
    let block_pairs = encoder::build_block_map(trace);
    let block_map: HashMap<String, String> = block_pairs
        .into_iter()
        .map(|(hash, name)| (name, hash))
        .collect();

    let correct_nodes = decoder::identify_correct_nodes(final_state);
    Ok(decoder::extract_expected_state(
        final_state,
        &correct_nodes,
        &block_map,
    ))
}

