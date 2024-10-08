use std::sync::{Arc, Mutex};
use tracing_subscriber::fmt::MakeWriter;

/// Appends logs to a provided vector.
pub struct Writer {
    logs: Arc<Mutex<Vec<String>>>,
}

impl Writer {
    /// Creates a new `Writer` instance.
    pub fn new(logs: Arc<Mutex<Vec<String>>>) -> Self {
        Self { logs }
    }

    /// Adds fields that weren't previously handled to the log message.
    fn add_to_log_message(key: &str, value: &serde_json::Value, log_message: &mut String) {
        if let serde_json::Value::Object(map) = value {
            for (key, value) in map {
                Self::add_to_log_message(key, value, log_message);
            }
        } else if !key.is_empty()
            && key != "level"
            && key != "timestamp"
            && key != "target"
            && key != "message"
        {
            log_message.push_str(&format!("{}={} ", key, value));
        }
    }
}

impl std::io::Write for Writer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // Process JSON
        let json_str = String::from_utf8_lossy(buf);
        let json: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        // Create log message
        let level = json["level"].as_str().unwrap();
        let timestamp = json["timestamp"].as_str().unwrap();
        let target = json["target"].as_str().unwrap();
        let msg = json["fields"]["message"].as_str().unwrap();
        let mut log_message = format!(
            "[{}|{}] {} => {} (",
            chrono::NaiveDateTime::parse_from_str(timestamp, "%Y-%m-%dT%H:%M:%S%.6fZ")
                .unwrap()
                .format("%m/%d %H:%M:%S"),
            level,
            target,
            msg,
        );

        // Add remaning fields
        Self::add_to_log_message("", &json, &mut log_message);
        let log_message = format!("{})", log_message.trim_end());

        // Cleanup empty logs
        let log_message = log_message.replace("()", "");

        // Append log message
        let mut logs = self.logs.lock().unwrap();
        logs.push(log_message.trim_end().to_string());
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Writer {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        Writer {
            logs: Arc::clone(&self.logs),
        }
    }
}
