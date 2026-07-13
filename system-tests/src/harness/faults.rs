// SPDX-License-Identifier: Apache-2.0

use crate::harness::{
    backend::{ClusterBackend, Fault},
    events::EventRecorder,
};
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Duration};

const MAX_SCHEDULE_ENTRIES: usize = 64;
const MAX_OFFSET_MS: u64 = 10 * 60 * 1000;
const MAX_DURATION_MS: u64 = 5 * 60 * 1000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaultScheduleEntry {
    pub offset_ms: u64,
    pub duration_ms: u64,
    pub fault: Fault,
}

pub struct NemesisScheduler {
    backend: Arc<dyn ClusterBackend>,
    events: Arc<EventRecorder>,
    schedule: Vec<FaultScheduleEntry>,
}

impl NemesisScheduler {
    pub fn new(
        backend: Arc<dyn ClusterBackend>,
        events: Arc<EventRecorder>,
        mut schedule: Vec<FaultScheduleEntry>,
    ) -> Result<Self> {
        if schedule.is_empty() || schedule.len() > MAX_SCHEDULE_ENTRIES {
            bail!("fault schedule must contain 1 to {MAX_SCHEDULE_ENTRIES} entries");
        }
        if schedule.iter().any(|entry| {
            entry.offset_ms > MAX_OFFSET_MS
                || entry.duration_ms == 0
                || entry.duration_ms > MAX_DURATION_MS
        }) {
            bail!("fault schedule offset or duration exceeds its bound");
        }
        schedule.sort_by_key(|entry| entry.offset_ms);
        Ok(Self {
            backend,
            events,
            schedule,
        })
    }

    pub async fn run(self) -> Result<()> {
        let started = tokio::time::Instant::now();
        let mut tasks = tokio::task::JoinSet::new();
        for entry in self.schedule {
            let backend = self.backend.clone();
            let events = self.events.clone();
            tasks.spawn(async move {
                tokio::time::sleep_until(started + Duration::from_millis(entry.offset_ms)).await;
                let fault_id = entry.fault.stable_id();
                events.record("fault", serde_json::json!({
                    "fault_id":fault_id,"fault_action":"apply","details":{"fault":entry.fault,"duration_ms":entry.duration_ms}
                }))?;
                let guard = backend.apply_fault(entry.fault.clone()).await?;
                tokio::time::sleep(Duration::from_millis(entry.duration_ms)).await;
                guard.heal().await?;
                events.record("fault", serde_json::json!({
                    "fault_id":fault_id,"fault_action":"heal"
                }))?;
                Result::<()>::Ok(())
            });
        }
        let mut first_error = None;
        while let Some(result) = tasks.join_next().await {
            let result = result
                .map_err(anyhow::Error::from)
                .and_then(|result| result);
            if first_error.is_none() {
                first_error = result.err();
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

pub fn deterministic_fault(seed: u64, step: u64, choices: &[Fault]) -> Result<Fault> {
    if choices.is_empty() {
        bail!("nemesis choices cannot be empty");
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"pepper-system-nemesis-v1");
    hasher.update(&seed.to_be_bytes());
    hasher.update(&step.to_be_bytes());
    let digest = hasher.finalize();
    let mut index = [0u8; 8];
    index.copy_from_slice(&digest.as_bytes()[..8]);
    Ok(choices[(u64::from_be_bytes(index) as usize) % choices.len()].clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness::cluster::NodeId;

    #[test]
    fn deterministic_choice_is_reproducible_and_bounded() {
        let choices = vec![
            Fault::Pause {
                node: NodeId::new("a").unwrap(),
            },
            Fault::Kill {
                node: NodeId::new("b").unwrap(),
            },
        ];
        assert_eq!(
            deterministic_fault(42, 7, &choices).unwrap().stable_id(),
            deterministic_fault(42, 7, &choices).unwrap().stable_id()
        );
        assert!(deterministic_fault(42, 7, &[]).is_err());
    }
}
