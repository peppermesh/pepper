// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::{Map, Value};
use std::{
    fs::{File, OpenOptions},
    io::{BufWriter, Write},
    path::Path,
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

#[derive(Debug, Serialize)]
struct Event<'a> {
    schema_version: u8,
    run_id: &'a str,
    sequence: u64,
    #[serde(rename = "type")]
    event_type: &'a str,
    controller_monotonic_ns: u64,
    wall_time_rfc3339: String,
    #[serde(flatten)]
    details: Map<String, Value>,
}

pub struct EventRecorder {
    run_id: String,
    started: Instant,
    sequence: AtomicU64,
    writer: Mutex<BufWriter<File>>,
}

impl EventRecorder {
    pub fn create(run_id: impl Into<String>, path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)
            .with_context(|| format!("failed to create event log {}", path.display()))?;
        Ok(Self {
            run_id: run_id.into(),
            started: Instant::now(),
            sequence: AtomicU64::new(0),
            writer: Mutex::new(BufWriter::new(file)),
        })
    }

    pub fn record<T: Serialize>(&self, event_type: &str, details: T) -> Result<u64> {
        let sequence = self.sequence.fetch_add(1, Ordering::AcqRel);
        let details = serde_json::to_value(details)?;
        let Value::Object(details) = details else {
            anyhow::bail!("event details must serialize as an object");
        };
        let event = Event {
            schema_version: 1,
            run_id: &self.run_id,
            sequence,
            event_type,
            controller_monotonic_ns: self.started.elapsed().as_nanos().min(u128::from(u64::MAX))
                as u64,
            wall_time_rfc3339: OffsetDateTime::now_utc().format(&Rfc3339)?,
            details,
        };
        let mut writer = self
            .writer
            .lock()
            .map_err(|_| anyhow::anyhow!("event log mutex poisoned"))?;
        serde_json::to_writer(&mut *writer, &event)?;
        writer.write_all(b"\n")?;
        writer.flush()?;
        Ok(sequence)
    }

    pub fn sync(&self) -> Result<()> {
        let mut writer = self
            .writer
            .lock()
            .map_err(|_| anyhow::anyhow!("event log mutex poisoned"))?;
        writer.flush()?;
        writer.get_ref().sync_all()?;
        Ok(())
    }
}
