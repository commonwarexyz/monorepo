//! Utility functions for traces

use commonware_cryptography::{Hasher as _, Sha256};
use opentelemetry::{
    trace::{SpanContext, SpanId, TraceContextExt, TraceFlags, TraceId, TraceState},
    Context,
};
use tracing::Span;
use tracing_opentelemetry::OpenTelemetrySpanExt;

pub mod status;

#[cfg(any(test, feature = "test-utils"))]
pub mod collector;

/// Roots `span` in a deterministic trace identified by its name and `value`.
///
/// `tracing` assigns each root span a random OTLP trace id, so the same logical
/// operation running on different instances lands in unrelated traces. Calling
/// this with a value that every instance derives identically (e.g. from a
/// consensus round) places matching spans for that operation in one trace, which
/// lets multi-instance trace tooling lay each instance out on its own lane. The
/// span name and value are hashed into a deterministic trace id and attached via
/// a synthetic remote parent, so the span's descendants inherit it.
pub fn correlate(span: &Span, value: impl AsRef<[u8]>) {
    // Skip the hash when the span is not recording, since set_parent is a no-op
    if span.is_disabled() {
        return;
    }

    let namespace = span
        .metadata()
        .map(|metadata| metadata.name().as_bytes())
        .unwrap_or_default();
    let value = value.as_ref();
    let namespace_len = u64::try_from(namespace.len())
        .expect("namespace length should fit in u64")
        .to_be_bytes();

    let mut hasher = Sha256::new();
    hasher
        .update(&namespace_len)
        .update(namespace)
        .update(value);
    let digest = hasher.finalize();
    let digest = digest.as_ref();

    let mut trace_id = [0u8; 16];
    trace_id.copy_from_slice(&digest[..16]);
    if trace_id == [0u8; 16] {
        trace_id[15] = 1;
    }

    let mut parent_id = [0u8; 8];
    parent_id.copy_from_slice(&digest[16..24]);
    if parent_id == [0u8; 8] {
        parent_id[7] = 1;
    }

    let parent = Context::new().with_remote_span_context(SpanContext::new(
        TraceId::from_bytes(trace_id),
        SpanId::from_bytes(parent_id),
        TraceFlags::SAMPLED,
        true,
        TraceState::default(),
    ));
    let _ = span.set_parent(parent);
}

/// Records an integer as a numeric tracing field.
///
/// `tracing-opentelemetry` serializes `u64` and `Display`/`Debug` span fields as
/// strings, so integers must be recorded as `i64` to stay range-queryable and
/// correctly sorted in TraceQL. Record integer fields as `field = value.traced()`.
pub trait TracedExt {
    /// Returns `self` as an `i64` for use as a tracing field value.
    fn traced(self) -> i64;
}

macro_rules! impl_traced {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl TracedExt for $ty {
                fn traced(self) -> i64 {
                    i64::try_from(self).unwrap_or(i64::MAX)
                }
            }
        )+
    };
}

macro_rules! impl_traced_signed {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl TracedExt for $ty {
                fn traced(self) -> i64 {
                    i64::try_from(self).unwrap_or(if self < 0 {
                        i64::MIN
                    } else {
                        i64::MAX
                    })
                }
            }
        )+
    };
}

impl_traced!(u8, u16, u32, u64, u128, usize);
impl_traced_signed!(i8, i16, i32, i64, i128, isize);

#[cfg(test)]
mod tests {
    use super::correlate;
    use opentelemetry::trace::{TraceContextExt as _, TraceId, TracerProvider as _};
    use opentelemetry_sdk::trace::{Sampler, SdkTracerProvider};
    use tracing::Span;
    use tracing_opentelemetry::OpenTelemetrySpanExt as _;
    use tracing_subscriber::layer::SubscriberExt as _;

    fn trace_id_of(span: &Span) -> TraceId {
        span.context().span().span_context().trace_id()
    }

    #[test]
    fn correlate_assigns_deterministic_trace_id() {
        let provider = SdkTracerProvider::builder()
            .with_sampler(Sampler::AlwaysOn)
            .build();
        let subscriber = tracing_subscriber::registry()
            .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("test")));
        tracing::subscriber::with_default(subscriber, || {
            // Two instances entering the same logical operation derive the same id.
            let id = [7u8, 42u8];
            let a = tracing::info_span!("simplex.voter.view");
            correlate(&a, id);
            let b = tracing::info_span!("simplex.voter.view");
            correlate(&b, id);
            let expected = trace_id_of(&a);
            assert_ne!(expected, TraceId::INVALID);
            assert_eq!(trace_id_of(&a), trace_id_of(&b));

            // A different view yields a different trace.
            let c = tracing::info_span!("simplex.voter.view");
            correlate(&c, [7u8, 43u8]);
            assert_ne!(trace_id_of(&c), expected);

            // A different span name also yields a different trace.
            let d = tracing::info_span!("simplex.voter.view.other");
            correlate(&d, id);
            assert_ne!(trace_id_of(&d), expected);

            // The span-name boundary is explicit.
            let e = tracing::info_span!("runtime.trace.ab");
            correlate(&e, b"c");
            let f = tracing::info_span!("runtime.trace.a");
            correlate(&f, b"bc");
            assert_ne!(trace_id_of(&e), trace_id_of(&f));

            // A child span inherits the correlated trace id.
            let child = a.in_scope(|| tracing::info_span!("simplex.voter.propose"));
            assert_eq!(trace_id_of(&child), expected);
        });
    }
}
