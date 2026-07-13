// SPDX-License-Identifier: Apache-2.0

use crate::{
    harness::{artifacts::RunArtifacts, events::EventRecorder},
    oracles::linearizability::{HistoryOperation, KvOperation, KvResult, validate_history_ids},
};
use anyhow::{Result, anyhow};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};

#[derive(Debug)]
pub struct Invocation {
    id: String,
    client_id: String,
    invoked_ns: u64,
    operation: KvOperation,
    explicitly_stale: bool,
}

pub struct OperationHistory {
    started: Instant,
    sequence: AtomicU64,
    operations: Mutex<Vec<HistoryOperation>>,
    events: Arc<EventRecorder>,
}

impl OperationHistory {
    pub fn new(events: Arc<EventRecorder>) -> Self {
        Self {
            started: Instant::now(),
            sequence: AtomicU64::new(0),
            operations: Mutex::new(Vec::new()),
            events,
        }
    }

    pub fn invoke(
        &self,
        client_id: impl Into<String>,
        operation: KvOperation,
    ) -> Result<Invocation> {
        self.invoke_with_consistency(client_id, operation, false)
    }

    pub fn invoke_stale(
        &self,
        client_id: impl Into<String>,
        operation: KvOperation,
    ) -> Result<Invocation> {
        self.invoke_with_consistency(client_id, operation, true)
    }

    fn invoke_with_consistency(
        &self,
        client_id: impl Into<String>,
        operation: KvOperation,
        explicitly_stale: bool,
    ) -> Result<Invocation> {
        let id = format!(
            "history-{:08}",
            self.sequence.fetch_add(1, Ordering::AcqRel)
        );
        let client_id = client_id.into();
        let invoked_ns = nanos(self.started.elapsed());
        self.events.record("invoke", serde_json::json!({"operation_id":id,"attempt":1,"operation":"kv_history","node_id":client_id,"details":{"input":operation,"explicitly_stale":explicitly_stale}}))?;
        Ok(Invocation {
            id,
            client_id,
            invoked_ns,
            operation,
            explicitly_stale,
        })
    }

    pub fn complete(&self, invocation: Invocation, result: KvResult) -> Result<()> {
        let completed_ns = nanos(self.started.elapsed()).max(invocation.invoked_ns);
        self.events.record("complete", serde_json::json!({"operation_id":invocation.id,"attempt":1,"operation":"kv_history","node_id":invocation.client_id,"result":"ok","details":{"output":result,"invoked_ns":invocation.invoked_ns,"completed_ns":completed_ns,"explicitly_stale":invocation.explicitly_stale}}))?;
        self.operations
            .lock()
            .map_err(|_| anyhow!("operation history mutex poisoned"))?
            .push(HistoryOperation {
                id: invocation.id,
                client_id: invocation.client_id,
                invoked_ns: invocation.invoked_ns,
                completed_ns,
                operation: invocation.operation,
                result,
                explicitly_stale: invocation.explicitly_stale,
            });
        Ok(())
    }

    pub fn snapshot(&self) -> Result<Vec<HistoryOperation>> {
        let mut operations = self
            .operations
            .lock()
            .map_err(|_| anyhow!("operation history mutex poisoned"))?
            .clone();
        operations.sort_by_key(|operation| {
            (
                operation.invoked_ns,
                operation.completed_ns,
                operation.id.clone(),
            )
        });
        validate_history_ids(&operations).map_err(anyhow::Error::msg)?;
        Ok(operations)
    }

    pub fn write_artifact(
        &self,
        artifacts: &RunArtifacts,
        relative: &str,
    ) -> Result<Vec<HistoryOperation>> {
        let operations = self.snapshot()?;
        artifacts.write_json(relative, &serde_json::json!({"history_version":1,"clock":"controller_monotonic_ns","operations":operations}))?;
        Ok(operations)
    }
}

fn nanos(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}
