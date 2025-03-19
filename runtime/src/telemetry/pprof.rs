// Inspired by: https://github.com/grafana/pyroscope-rs/blob/main/pyroscope_backends/pyroscope_pprofrs/src/lib.rs
//
// pyroscope-rs uses a fork of pprof that isn't public (odd), we prefer to use the canonical pprof crate.

use pprof::{ProfilerGuard, ProfilerGuardBuilder};
use pyroscope::{
    backend::{
        Backend, BackendConfig, BackendImpl, BackendUninitialized, Report, Rule, Ruleset,
        StackBuffer, StackFrame, StackTrace,
    },
    error::{PyroscopeError, Result},
};
use std::{
    collections::HashMap,
    ffi::OsStr,
    ops::Deref,
    sync::{Arc, Mutex},
};
use tracing::trace;

const LOG_TAG: &str = "Pyroscope::Pprofrs";

pub fn pprof_backend(config: PprofConfig) -> BackendImpl<BackendUninitialized> {
    let backend_config = config.backend_config;
    BackendImpl::new(Box::new(Pprof::new(config)), Some(backend_config))
}

/// Pprof Configuration
#[derive(Debug)]
pub struct PprofConfig {
    sample_rate: u32,
    backend_config: BackendConfig,
}

impl Default for PprofConfig {
    fn default() -> Self {
        PprofConfig {
            sample_rate: 100,
            backend_config: BackendConfig::default(),
        }
    }
}

impl PprofConfig {
    /// Create a new Pprof configuration
    pub fn new() -> Self {
        PprofConfig::default()
    }

    /// Set the sample rate
    pub fn sample_rate(self, sample_rate: u32) -> Self {
        PprofConfig {
            sample_rate,
            ..self
        }
    }

    /// Tag thread id in report
    pub fn report_thread_id(self) -> Self {
        let backend_config = BackendConfig {
            report_thread_id: true,
            ..self.backend_config
        };

        PprofConfig {
            backend_config,
            ..self
        }
    }

    /// Tag thread name in report
    pub fn report_thread_name(self) -> Self {
        let backend_config = BackendConfig {
            report_thread_name: true,
            ..self.backend_config
        };

        PprofConfig {
            backend_config,
            ..self
        }
    }
}

/// Pprof Backend
#[derive(Default)]
pub struct Pprof<'a> {
    /// Profling buffer
    buffer: Arc<Mutex<StackBuffer>>,
    /// pprof-rs Configuration
    config: PprofConfig,
    /// Backend Configuration
    backend_config: BackendConfig,
    /// pprof-rs profiler Guard Builder
    inner_builder: Arc<Mutex<Option<ProfilerGuardBuilder>>>,
    /// pprof-rs profiler Guard
    guard: Arc<Mutex<Option<ProfilerGuard<'a>>>>,
    /// Ruleset
    ruleset: Ruleset,
}

impl std::fmt::Debug for Pprof<'_> {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        write!(fmt, "Pprof Backend")
    }
}

impl Pprof<'_> {
    /// Create a new Pprof Backend
    pub fn new(config: PprofConfig) -> Self {
        let backend_config = config.backend_config;
        Pprof {
            buffer: Arc::new(Mutex::new(StackBuffer::default())),
            config,
            backend_config,
            inner_builder: Arc::new(Mutex::new(None)),
            guard: Arc::new(Mutex::new(None)),
            ruleset: Ruleset::default(),
        }
    }
}

impl Backend for Pprof<'_> {
    fn spy_name(&self) -> std::result::Result<String, PyroscopeError> {
        Ok("pyroscope-rs".to_string())
    }

    fn spy_extension(&self) -> std::result::Result<Option<String>, PyroscopeError> {
        Ok(Some("cpu".to_string()))
    }

    fn sample_rate(&self) -> Result<u32> {
        Ok(self.config.sample_rate)
    }

    fn shutdown(self: Box<Self>) -> Result<()> {
        trace!(target: LOG_TAG, "Shutting down sampler thread");
        //drop(self.guard.take());

        Ok(())
    }

    fn initialize(&mut self) -> Result<()> {
        // Construct a ProfilerGuardBuilder
        let profiler = ProfilerGuardBuilder::default().frequency(self.config.sample_rate as i32);

        // Set inner_builder field
        *self.inner_builder.lock()? = Some(profiler);

        *self.guard.lock()? = Some(
            self.inner_builder
                .lock()?
                .as_ref()
                .ok_or_else(|| PyroscopeError::new("pprof-rs: ProfilerGuardBuilder error"))?
                .clone()
                .build()
                .map_err(|e| PyroscopeError::new(e.to_string().as_str()))?,
        );

        Ok(())
    }

    fn report(&mut self) -> Result<Vec<Report>> {
        self.dump_report()?;

        let buffer = self.buffer.clone();

        let report: StackBuffer = buffer.lock()?.deref().to_owned();

        let reports: Vec<Report> = report.into();

        buffer.lock()?.clear();

        Ok(reports)
    }

    fn set_config(&self, _config: BackendConfig) {}

    fn get_config(&self) -> Result<BackendConfig> {
        Ok(self.backend_config)
    }

    fn add_rule(&self, rule: Rule) -> Result<()> {
        if self.guard.lock()?.as_ref().is_some() {
            self.dump_report()?;
        }

        self.ruleset.add_rule(rule)?;

        Ok(())
    }

    fn remove_rule(&self, rule: Rule) -> Result<()> {
        if self.guard.lock()?.as_ref().is_some() {
            self.dump_report()?;
        }

        self.ruleset.remove_rule(rule)?;

        Ok(())
    }
}

impl Pprof<'_> {
    /// Workaround for pprof-rs to interupt the profiler
    pub fn dump_report(&self) -> Result<()> {
        let report = self
            .guard
            .lock()?
            .as_ref()
            .ok_or_else(|| PyroscopeError::new("pprof-rs: ProfilerGuard report error"))?
            .report()
            .build()
            .map_err(|e| PyroscopeError::new(e.to_string().as_str()))?;

        let stack_buffer = Into::<StackBuffer>::into(Into::<StackBufferWrapper>::into((
            report,
            &self.backend_config,
        )));

        // apply ruleset to stack_buffer
        let data: HashMap<StackTrace, usize> = stack_buffer
            .data
            .iter()
            .map(|(stacktrace, ss)| {
                let stacktrace = stacktrace.to_owned() + &self.ruleset;
                (stacktrace, ss.to_owned())
            })
            .collect();

        let buffer = self.buffer.clone();

        for (stacktrace, count) in data {
            buffer.lock()?.record_with_count(stacktrace, count)?;
        }

        self.reset()?;

        Ok(())
    }

    pub fn reset(&self) -> Result<()> {
        drop(self.guard.lock()?.take());

        *self.guard.lock()? = Some(
            self.inner_builder
                .lock()?
                .as_ref()
                .ok_or_else(|| PyroscopeError::new("pprof-rs: ProfilerGuardBuilder error"))?
                .clone()
                .build()
                .map_err(|e| PyroscopeError::new(e.to_string().as_str()))?,
        );

        Ok(())
    }
}

struct StackBufferWrapper(StackBuffer);

impl From<StackBufferWrapper> for StackBuffer {
    fn from(stackbuffer: StackBufferWrapper) -> Self {
        stackbuffer.0
    }
}

impl From<(pprof::Report, &BackendConfig)> for StackBufferWrapper {
    fn from(arg: (pprof::Report, &BackendConfig)) -> Self {
        let (report, config) = arg;
        //convert report to stackbuffer
        let buffer_data: HashMap<StackTrace, usize> = report
            .data
            .iter()
            .map(|(key, value)| {
                (
                    Into::<StackTraceWrapper>::into((key.to_owned(), config)).into(),
                    value.to_owned() as usize,
                )
            })
            .collect();
        StackBufferWrapper(StackBuffer::new(buffer_data))
    }
}

struct StackTraceWrapper(StackTrace);

impl From<StackTraceWrapper> for StackTrace {
    fn from(stack_trace: StackTraceWrapper) -> Self {
        stack_trace.0
    }
}

impl From<(pprof::Frames, &BackendConfig)> for StackTraceWrapper {
    fn from(arg: (pprof::Frames, &BackendConfig)) -> Self {
        let (frames, config) = arg;
        StackTraceWrapper(StackTrace::new(
            config,
            None,
            Some(frames.thread_id),
            Some(frames.thread_name),
            frames
                .frames
                .concat()
                .iter()
                .map(|frame| Into::<StackFrameWrapper>::into(frame.to_owned()).into())
                .collect(),
        ))
    }
}

struct StackFrameWrapper(StackFrame);

impl From<StackFrameWrapper> for StackFrame {
    fn from(stack_frame: StackFrameWrapper) -> Self {
        stack_frame.0
    }
}

impl From<pprof::Symbol> for StackFrameWrapper {
    fn from(symbol: pprof::Symbol) -> Self {
        StackFrameWrapper(StackFrame::new(
            None,
            Some(symbol.name()),
            Some(
                symbol
                    .filename
                    .clone()
                    .unwrap_or_default()
                    .file_name()
                    .unwrap_or_else(|| OsStr::new(""))
                    .to_str()
                    .unwrap_or("")
                    .to_string(),
            ),
            Some(
                symbol
                    .filename
                    .unwrap_or_default()
                    .to_str()
                    .unwrap_or("")
                    .to_string(),
            ),
            None,
            symbol.lineno,
        ))
    }
}
