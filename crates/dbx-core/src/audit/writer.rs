//! Bounded, asynchronous writer for the SQLite audit log.
//!
//! `record` never awaits and never touches SQLite directly. A single writer
//! task batches events and inserts them in one transaction, which keeps the
//! hash chain serialized and keeps audit I/O off the query hot path.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};

use super::{AuditDurableFuture, AuditEventInsert, AuditSink};
use crate::persistence::storage::Storage;

const DEFAULT_BATCH_SIZE: usize = 128;
const DEFAULT_FLUSH_INTERVAL: Duration = Duration::from_millis(50);

enum AuditMessage {
    Event(AuditEventInsert),
    /// Fail-closed path: the writer must commit this event before acknowledging.
    Durable(AuditEventInsert, oneshot::Sender<Result<(), String>>),
    Flush(oneshot::Sender<Result<(), String>>),
}

pub struct SqliteAuditSink {
    tx: mpsc::Sender<AuditMessage>,
    healthy: Arc<AtomicBool>,
    dropped: Arc<AtomicU64>,
}

impl SqliteAuditSink {
    /// Starts the writer task. Must be called from inside a Tokio runtime.
    pub fn spawn(storage: Storage, capacity: usize) -> Self {
        let (tx, rx) = mpsc::channel(capacity.max(1));
        let healthy = Arc::new(AtomicBool::new(true));
        let dropped = Arc::new(AtomicU64::new(0));
        let writer_healthy = healthy.clone();
        tokio::spawn(async move {
            writer_loop(storage, rx, writer_healthy).await;
        });
        Self { tx, healthy, dropped }
    }

    pub fn dropped_count(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Waits until every event queued before this call has been committed.
    /// CLI and other short-lived processes call this before exit.
    pub async fn flush_async(&self) -> Result<(), String> {
        let (tx, rx) = oneshot::channel();
        self.tx.send(AuditMessage::Flush(tx)).await.map_err(|_| "AUDIT_SINK_CLOSED".to_string())?;
        rx.await.map_err(|_| "AUDIT_SINK_CLOSED".to_string())?
    }
}

impl AuditSink for SqliteAuditSink {
    fn record(&self, event: AuditEventInsert) -> Result<(), String> {
        match self.tx.try_send(AuditMessage::Event(event)) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                Err("AUDIT_QUEUE_FULL".to_string())
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.healthy.store(false, Ordering::SeqCst);
                Err("AUDIT_SINK_CLOSED".to_string())
            }
        }
    }

    fn append_durable(&self, event: AuditEventInsert) -> AuditDurableFuture<'_> {
        Box::pin(async move {
            let (reply, result) = oneshot::channel();
            // Use `send` (not `try_send`): fail-closed must wait for capacity
            // or fail rather than silently drop the event.
            self.tx.send(AuditMessage::Durable(event, reply)).await.map_err(|_| "AUDIT_SINK_CLOSED".to_string())?;
            result.await.map_err(|_| "AUDIT_SINK_CLOSED".to_string())?
        })
    }

    fn is_durable(&self) -> bool {
        true
    }

    fn flush(&self) -> Result<(), String> {
        // The synchronous trait method only signals the writer. Callers that
        // need a durability guarantee use `flush_async`.
        let (tx, _rx) = oneshot::channel();
        self.tx.try_send(AuditMessage::Flush(tx)).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => "AUDIT_QUEUE_FULL".to_string(),
            mpsc::error::TrySendError::Closed(_) => "AUDIT_SINK_CLOSED".to_string(),
        })
    }

    fn flush_durable(&self) -> AuditDurableFuture<'_> {
        Box::pin(async move { self.flush_async().await })
    }

    fn healthy(&self) -> bool {
        self.healthy.load(Ordering::SeqCst)
    }
}

async fn writer_loop(storage: Storage, mut rx: mpsc::Receiver<AuditMessage>, healthy: Arc<AtomicBool>) {
    let mut batch: Vec<AuditEventInsert> = Vec::with_capacity(DEFAULT_BATCH_SIZE);
    while let Some(message) = rx.recv().await {
        match message {
            AuditMessage::Event(event) => {
                batch.push(event);
                let deadline = tokio::time::sleep(DEFAULT_FLUSH_INTERVAL);
                tokio::pin!(deadline);
                while batch.len() < DEFAULT_BATCH_SIZE {
                    tokio::select! {
                        maybe = rx.recv() => {
                            match maybe {
                                Some(AuditMessage::Event(event)) => batch.push(event),
                                Some(AuditMessage::Durable(event, reply)) => {
                                    let pending = flush_batch(&storage, &mut batch).await;
                                    let result = match pending {
                                        Ok(()) => {
                                            let mut single = vec![event];
                                            flush_batch(&storage, &mut single).await
                                        }
                                        Err(error) => Err(error),
                                    };
                                    healthy.store(result.is_ok(), Ordering::SeqCst);
                                    let _ = reply.send(result);
                                }
                                Some(AuditMessage::Flush(reply)) => {
                                    let had_pending = !batch.is_empty();
                                    let result = flush_batch(&storage, &mut batch).await;
                                    if result.is_ok() && had_pending {
                                        healthy.store(true, Ordering::SeqCst);
                                    } else if result.is_err() {
                                        healthy.store(false, Ordering::SeqCst);
                                    }
                                    let _ = reply.send(result);
                                }
                                None => break,
                            }
                        }
                        _ = &mut deadline => break,
                    }
                }
                let had_pending = !batch.is_empty();
                match flush_batch(&storage, &mut batch).await {
                    Ok(()) => {
                        if had_pending {
                            healthy.store(true, Ordering::SeqCst);
                        }
                    }
                    Err(error) => {
                        healthy.store(false, Ordering::SeqCst);
                        log::error!("[audit] batch write failed: {error}");
                    }
                }
            }
            AuditMessage::Durable(event, reply) => {
                let pending = flush_batch(&storage, &mut batch).await;
                let result = match pending {
                    Ok(()) => {
                        let mut single = vec![event];
                        flush_batch(&storage, &mut single).await
                    }
                    Err(error) => Err(error),
                };
                healthy.store(result.is_ok(), Ordering::SeqCst);
                let _ = reply.send(result);
            }
            AuditMessage::Flush(reply) => {
                let had_pending = !batch.is_empty();
                let result = flush_batch(&storage, &mut batch).await;
                if result.is_ok() && had_pending {
                    healthy.store(true, Ordering::SeqCst);
                } else if result.is_err() {
                    healthy.store(false, Ordering::SeqCst);
                }
                let _ = reply.send(result);
            }
        }
    }
    let had_pending = !batch.is_empty();
    if let Err(error) = flush_batch(&storage, &mut batch).await {
        healthy.store(false, Ordering::SeqCst);
        log::error!("[audit] final batch write failed: {error}");
    } else if had_pending {
        healthy.store(true, Ordering::SeqCst);
    }
}

async fn flush_batch(storage: &Storage, batch: &mut Vec<AuditEventInsert>) -> Result<(), String> {
    if batch.is_empty() {
        return Ok(());
    }
    let events = std::mem::take(batch);
    match storage.insert_audit_events_batch(events.clone()).await {
        Ok(_) => Ok(()),
        Err(error) => {
            // The batch transaction rolled back as a whole. Keep the events so
            // the next flush can retry; silently dropping them would make the
            // audit trail lossy even before fail-open/fail-closed is chosen.
            batch.extend(events);
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{Actor, AuditContext, AuditDecision, AuditOperation, AuditOutcome, AuditSource};

    async fn storage() -> Storage {
        let path = std::env::temp_dir().join(format!("dbx-audit-writer-{}.db", uuid::Uuid::new_v4()));
        crate::persistence::test_storage::open(&path).await.unwrap()
    }

    fn event(id: &str) -> AuditEventInsert {
        let context = AuditContext {
            actor: Actor::bootstrap(),
            source: AuditSource::Web,
            client_ip: None,
            user_agent: None,
            request_id: None,
            execution_id: None,
        };
        let mut event =
            AuditEventInsert::new(&context, AuditOperation::Query, AuditDecision::Allowed, AuditOutcome::Success);
        event.event_id = id.to_string();
        event.sql_text = Some(format!("SELECT '{id}'"));
        event
    }

    #[tokio::test]
    async fn flush_waits_for_the_batch_and_preserves_order() {
        let storage = storage().await;
        let sink = SqliteAuditSink::spawn(storage.clone(), 16);
        sink.record(event("e1")).unwrap();
        sink.record(event("e2")).unwrap();
        sink.flush_async().await.unwrap();
        let head = storage.audit_chain_head().await.unwrap();
        assert_eq!(head.last_seq, 2);
        assert_eq!(head.event_count, 2);
        assert!(sink.healthy());
        assert_eq!(sink.dropped_count(), 0);
    }

    #[tokio::test]
    async fn durable_append_commits_before_returning() {
        let storage = storage().await;
        let sink = SqliteAuditSink::spawn(storage.clone(), 16);
        assert!(sink.is_durable());
        sink.append_durable(event("durable-1")).await.unwrap();
        let head = storage.audit_chain_head().await.unwrap();
        assert_eq!(head.last_seq, 1);
        assert_eq!(head.event_count, 1);
    }

    #[tokio::test]
    async fn noop_is_never_durable_and_memory_is_durable_for_tests() {
        let noop = crate::audit::NoopAuditSink;
        assert!(!noop.is_durable());
        assert!(noop.append_durable(event("noop")).await.is_err());

        let memory = crate::audit::MemoryAuditSink::default();
        assert!(memory.is_durable());
        memory.append_durable(event("memory")).await.unwrap();
        assert_eq!(memory.events().len(), 1);
    }

    #[tokio::test]
    async fn a_full_queue_is_reported_instead_of_blocking() {
        let storage = storage().await;
        let sink = SqliteAuditSink::spawn(storage, 1);
        sink.record(event("e1")).unwrap();
        // The first event may already be in the writer; fill until the queue
        // reports backpressure. A tiny capacity makes this deterministic.
        let mut errors = 0;
        for index in 0..8 {
            if sink.record(event(&format!("extra-{index}"))).is_err() {
                errors += 1;
                break;
            }
            tokio::task::yield_now().await;
        }
        let _ = sink.flush_async().await;
        assert!(errors > 0 || sink.dropped_count() > 0, "bounded queue must surface backpressure");
    }
}
