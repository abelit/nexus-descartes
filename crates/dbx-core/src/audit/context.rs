//! Task-local propagation for the current audit context.
//!
//! Web, MCP, CLI, and AI entry points scope a context around their handler
//! future. The core reads it when it emits an event; explicit
//! `QueryExecutionOptions.audit` still wins because spawned tasks do not
//! inherit a task-local automatically.

use std::future::Future;

use super::AuditContext;

tokio::task_local! {
    static CURRENT_AUDIT_CONTEXT: AuditContext;
}

pub async fn with_audit_context<F>(context: AuditContext, future: F) -> F::Output
where
    F: Future,
{
    CURRENT_AUDIT_CONTEXT.scope(context, future).await
}

pub fn current_audit_context() -> Option<AuditContext> {
    CURRENT_AUDIT_CONTEXT.try_with(|context| context.clone()).ok()
}

/// Spawns a task with an explicit context. Use this instead of relying on
/// task-local inheritance across `tokio::spawn`.
pub fn spawn_with_audit_context<F>(context: AuditContext, future: F) -> tokio::task::JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    tokio::spawn(with_audit_context(context, future))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{Actor, AuditSource};

    fn context(id: &str) -> AuditContext {
        AuditContext {
            actor: Actor { id: id.to_string(), ..Actor::bootstrap() },
            source: AuditSource::Web,
            client_ip: None,
            user_agent: None,
            request_id: None,
            execution_id: None,
        }
    }

    #[tokio::test]
    async fn context_is_visible_across_awaits_and_explicit_spawns() {
        let context = context("alice");
        with_audit_context(context.clone(), async {
            tokio::task::yield_now().await;
            assert_eq!(current_audit_context().unwrap().actor.id, "alice");
            let spawned = spawn_with_audit_context(context.clone(), async {
                tokio::task::yield_now().await;
                current_audit_context().unwrap().actor.id
            });
            assert_eq!(spawned.await.unwrap(), "alice");
        })
        .await;
        assert!(current_audit_context().is_none());
    }
}
