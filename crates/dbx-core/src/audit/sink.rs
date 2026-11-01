use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;

use super::AuditEventInsert;

/// A boxed future returned by [`AuditSink::append_durable`].
pub type AuditDurableFuture<'a> = Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;

/// Destination for audit events.
///
/// `record` is the best-effort path: implementations must not block the
/// database execution path and may drop an event under backpressure.
/// `append_durable` is the fail-closed path: it returns only after the event
/// is committed to durable storage. The default implementation deliberately
/// fails, so a no-op or lossy sink can never make fail-closed mode look safe.
pub trait AuditSink: Send + Sync {
    fn record(&self, event: AuditEventInsert) -> Result<(), String>;

    /// Write one event and return only after it is durable.
    fn append_durable(&self, _event: AuditEventInsert) -> AuditDurableFuture<'_> {
        Box::pin(async { Err("AUDIT_SINK_NOT_DURABLE".to_string()) })
    }

    /// Whether `append_durable` is backed by a durable store.
    fn is_durable(&self) -> bool {
        false
    }

    /// Flush queued events. Short-lived processes call this before exit.
    fn flush(&self) -> Result<(), String>;

    /// Flush and return only once every queued event is committed.
    ///
    /// `flush` may only signal the writer; shutdown paths need this one so a
    /// process exit cannot drop the queue.
    fn flush_durable(&self) -> AuditDurableFuture<'_> {
        Box::pin(async { self.flush() })
    }

    fn healthy(&self) -> bool {
        true
    }
}

#[derive(Default)]
pub struct NoopAuditSink;

impl AuditSink for NoopAuditSink {
    fn record(&self, _event: AuditEventInsert) -> Result<(), String> {
        Ok(())
    }

    fn flush(&self) -> Result<(), String> {
        Ok(())
    }
}

/// Test sink that keeps every recorded event in memory.
#[derive(Default)]
pub struct MemoryAuditSink {
    events: Mutex<Vec<AuditEventInsert>>,
}

impl MemoryAuditSink {
    pub fn events(&self) -> Vec<AuditEventInsert> {
        self.events.lock().unwrap_or_else(|error| error.into_inner()).clone()
    }
}

impl AuditSink for MemoryAuditSink {
    fn record(&self, event: AuditEventInsert) -> Result<(), String> {
        self.events.lock().unwrap_or_else(|error| error.into_inner()).push(event);
        Ok(())
    }

    fn append_durable(&self, event: AuditEventInsert) -> AuditDurableFuture<'_> {
        Box::pin(async move { self.record(event) })
    }

    fn is_durable(&self) -> bool {
        // For tests, the in-memory sink is the durable store.
        true
    }

    fn flush(&self) -> Result<(), String> {
        Ok(())
    }
}
