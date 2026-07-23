// SPDX-License-Identifier: Apache-2.0

//! Deterministic single-database writer coordination state machine.
//!
//! A deployment applies these transitions on the namespace leader. Tickets
//! improve lock behavior and fairness; `guarded_commit` still compares the
//! exact protected head immediately before changing it.

use crate::SqliteError;
use pepper_types::{CODEC_SQLITE_SNAPSHOT, Cid};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WriterTicket {
    pub ticket_id: String,
    pub acquisition_id: String,
    pub database: String,
    pub holder: String,
    pub base_snapshot_cid: Cid,
    pub base_generation: u64,
    pub leader_term: u64,
    pub lease_epoch: u64,
    pub expires_at_millis: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum AcquisitionStatus {
    Queued {
        position: usize,
    },
    Granted {
        ticket: WriterTicket,
    },
    Busy,
    TimedOut,
    Stale {
        current_snapshot_cid: Cid,
        current_generation: u64,
    },
    Released,
    Fenced,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CommitAttempt {
    pub idempotency_key: String,
    pub ticket: WriterTicket,
    pub base_snapshot_cid: Cid,
    pub base_generation: u64,
    pub new_snapshot_cid: Cid,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CommitRecord {
    pub idempotency_key: String,
    pub base_snapshot_cid: Cid,
    pub base_generation: u64,
    pub snapshot_cid: Cid,
    pub generation: u64,
    pub leader_term: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum WriterControlRequest {
    Acquire {
        acquisition_id: String,
        session_id: String,
        base_snapshot_cid: Cid,
        base_generation: u64,
        now_millis: u64,
        wait_timeout_millis: u64,
        lease_millis: u64,
        max_waiters: usize,
    },
    Renew {
        ticket: WriterTicket,
        now_millis: u64,
    },
    Release {
        ticket: WriterTicket,
        now_millis: u64,
    },
    Status {
        acquisition_id: String,
        now_millis: u64,
    },
    CommitStatus {
        idempotency_key: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub enum WriterControlResponse {
    Acquisition { status: AcquisitionStatus },
    Renewed { ticket: WriterTicket },
    Released,
    Commit { record: Option<CommitRecord> },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GuardedCommitRequest {
    pub ticket: WriterTicket,
    pub base_snapshot_cid: Cid,
    pub base_generation: u64,
    pub new_snapshot_cid: Cid,
    pub idempotency_key: String,
    pub now_millis: u64,
}

#[derive(Debug, Clone)]
struct Waiter {
    acquisition_id: String,
    holder: String,
    base_snapshot_cid: Cid,
    base_generation: u64,
    deadline_millis: u64,
}

#[derive(Debug, Clone)]
pub struct WriterCoordinator {
    database: String,
    head_snapshot_cid: Cid,
    head_generation: u64,
    leader_term: u64,
    next_ticket: u64,
    lease_millis: u64,
    max_waiters: usize,
    active: Option<WriterTicket>,
    waiters: VecDeque<Waiter>,
    acquisitions: HashMap<String, AcquisitionStatus>,
    commits: HashMap<String, (CommitAttempt, CommitRecord)>,
}

impl WriterCoordinator {
    pub fn new(
        database: impl Into<String>,
        head_snapshot_cid: Cid,
        head_generation: u64,
        leader_term: u64,
        lease_millis: u64,
        max_waiters: usize,
    ) -> Result<Self, SqliteError> {
        let database = database.into();
        if database.is_empty()
            || head_snapshot_cid.codec != CODEC_SQLITE_SNAPSHOT
            || leader_term == 0
            || lease_millis == 0
            || max_waiters == 0
        {
            return Err(SqliteError::Invalid(
                "invalid writer coordinator configuration".into(),
            ));
        }
        Ok(Self {
            database,
            head_snapshot_cid,
            head_generation,
            leader_term,
            next_ticket: 1,
            lease_millis,
            max_waiters,
            active: None,
            waiters: VecDeque::new(),
            acquisitions: HashMap::new(),
            commits: HashMap::new(),
        })
    }

    pub fn head(&self) -> (&Cid, u64) {
        (&self.head_snapshot_cid, self.head_generation)
    }

    pub fn leader_term(&self) -> u64 {
        self.leader_term
    }

    pub fn active_ticket(&self) -> Option<&WriterTicket> {
        self.active.as_ref()
    }

    pub fn waiter_count(&self) -> usize {
        self.waiters.len()
    }

    pub fn validate_ticket(
        &mut self,
        ticket: &WriterTicket,
        now_millis: u64,
    ) -> Result<(), SqliteError> {
        self.advance(now_millis);
        self.validate_active(ticket, now_millis)
    }

    pub fn acquisition_status(&self, acquisition_id: &str) -> Option<&AcquisitionStatus> {
        self.acquisitions.get(acquisition_id)
    }

    pub fn commit_status(&self, idempotency_key: &str) -> Option<&CommitRecord> {
        self.commits.get(idempotency_key).map(|(_, record)| record)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn acquire(
        &mut self,
        acquisition_id: impl Into<String>,
        holder: impl Into<String>,
        base_snapshot_cid: Cid,
        base_generation: u64,
        now_millis: u64,
        wait_timeout_millis: u64,
    ) -> Result<AcquisitionStatus, SqliteError> {
        self.advance(now_millis);
        let acquisition_id = acquisition_id.into();
        let holder = holder.into();
        if acquisition_id.is_empty() || holder.is_empty() {
            return Err(SqliteError::Invalid(
                "acquisition and holder IDs must not be empty".into(),
            ));
        }
        if let Some(status) = self.acquisitions.get(&acquisition_id) {
            return Ok(status.clone());
        }
        if base_snapshot_cid != self.head_snapshot_cid || base_generation != self.head_generation {
            let status = self.stale_status();
            self.acquisitions.insert(acquisition_id, status.clone());
            return Ok(status);
        }
        if self.active.is_none() {
            let ticket = self.grant(
                acquisition_id.clone(),
                holder,
                base_snapshot_cid,
                base_generation,
                now_millis,
            )?;
            let status = AcquisitionStatus::Granted { ticket };
            self.acquisitions.insert(acquisition_id, status.clone());
            return Ok(status);
        }
        if wait_timeout_millis == 0 || self.waiters.len() >= self.max_waiters {
            let status = AcquisitionStatus::Busy;
            self.acquisitions.insert(acquisition_id, status.clone());
            return Ok(status);
        }
        let deadline_millis = now_millis
            .checked_add(wait_timeout_millis)
            .ok_or_else(|| SqliteError::Invalid("writer wait deadline overflow".into()))?;
        self.waiters.push_back(Waiter {
            acquisition_id: acquisition_id.clone(),
            holder,
            base_snapshot_cid,
            base_generation,
            deadline_millis,
        });
        let status = AcquisitionStatus::Queued {
            position: self.waiters.len(),
        };
        self.acquisitions.insert(acquisition_id, status.clone());
        Ok(status)
    }

    pub fn renew(
        &mut self,
        ticket: &WriterTicket,
        now_millis: u64,
    ) -> Result<WriterTicket, SqliteError> {
        self.advance(now_millis);
        self.validate_active(ticket, now_millis)?;
        let active = self.active.as_mut().expect("validated active ticket");
        active.lease_epoch = active
            .lease_epoch
            .checked_add(1)
            .ok_or_else(|| SqliteError::Invalid("writer lease epoch overflow".into()))?;
        active.expires_at_millis = now_millis
            .checked_add(self.lease_millis)
            .ok_or_else(|| SqliteError::Invalid("writer lease deadline overflow".into()))?;
        let renewed = active.clone();
        self.acquisitions.insert(
            renewed.acquisition_id.clone(),
            AcquisitionStatus::Granted {
                ticket: renewed.clone(),
            },
        );
        Ok(renewed)
    }

    pub fn release(&mut self, ticket: &WriterTicket, now_millis: u64) -> Result<(), SqliteError> {
        self.advance(now_millis);
        self.validate_active(ticket, now_millis)?;
        let released = self.active.take().expect("validated active ticket");
        self.acquisitions
            .insert(released.acquisition_id, AcquisitionStatus::Released);
        self.advance(now_millis);
        Ok(())
    }

    /// A disconnected local session cannot retain a cluster-wide writer.
    pub fn disconnect(&mut self, holder: &str, now_millis: u64) {
        self.advance(now_millis);
        if self
            .active
            .as_ref()
            .is_some_and(|ticket| ticket.holder == holder)
        {
            let released = self.active.take().expect("active ticket");
            self.acquisitions
                .insert(released.acquisition_id, AcquisitionStatus::Released);
        }
        self.waiters.retain(|waiter| {
            if waiter.holder == holder {
                self.acquisitions
                    .insert(waiter.acquisition_id.clone(), AcquisitionStatus::Released);
                false
            } else {
                true
            }
        });
        self.advance(now_millis);
    }

    /// A new leader term invalidates every ticket issued by the old leader.
    pub fn change_leader_term(
        &mut self,
        new_term: u64,
        now_millis: u64,
    ) -> Result<(), SqliteError> {
        if new_term <= self.leader_term {
            return Err(SqliteError::Invalid(
                "leader term must increase monotonically".into(),
            ));
        }
        self.advance(now_millis);
        if let Some(ticket) = self.active.take() {
            self.acquisitions
                .insert(ticket.acquisition_id, AcquisitionStatus::Fenced);
        }
        for waiter in self.waiters.drain(..) {
            self.acquisitions
                .insert(waiter.acquisition_id, AcquisitionStatus::Fenced);
        }
        self.leader_term = new_term;
        self.next_ticket = 1;
        Ok(())
    }

    /// Atomically checks ticket, term, lease, exact protected head, and
    /// idempotency before changing the database head.
    pub fn guarded_commit(
        &mut self,
        attempt: CommitAttempt,
        now_millis: u64,
    ) -> Result<CommitRecord, SqliteError> {
        if attempt.idempotency_key.is_empty()
            || attempt.new_snapshot_cid.codec != CODEC_SQLITE_SNAPSHOT
        {
            return Err(SqliteError::Invalid("invalid guarded commit".into()));
        }
        if let Some((prior_attempt, record)) = self.commits.get(&attempt.idempotency_key) {
            return if prior_attempt.base_snapshot_cid == attempt.base_snapshot_cid
                && prior_attempt.base_generation == attempt.base_generation
                && prior_attempt.new_snapshot_cid == attempt.new_snapshot_cid
            {
                Ok(record.clone())
            } else {
                Err(SqliteError::Invalid(
                    "idempotency key was reused for another commit".into(),
                ))
            };
        }
        self.advance(now_millis);
        self.validate_active(&attempt.ticket, now_millis)?;
        if attempt.base_snapshot_cid != self.head_snapshot_cid
            || attempt.base_generation != self.head_generation
            || attempt.ticket.base_snapshot_cid != attempt.base_snapshot_cid
            || attempt.ticket.base_generation != attempt.base_generation
        {
            return Err(SqliteError::GenerationConflict {
                current_generation: self.head_generation,
            });
        }
        let generation = self
            .head_generation
            .checked_add(1)
            .ok_or_else(|| SqliteError::Invalid("database generation overflow".into()))?;
        let record = CommitRecord {
            idempotency_key: attempt.idempotency_key.clone(),
            base_snapshot_cid: attempt.base_snapshot_cid.clone(),
            base_generation: attempt.base_generation,
            snapshot_cid: attempt.new_snapshot_cid.clone(),
            generation,
            leader_term: self.leader_term,
        };
        self.head_snapshot_cid = attempt.new_snapshot_cid.clone();
        self.head_generation = generation;
        let released = self.active.take().expect("validated active ticket");
        self.acquisitions
            .insert(released.acquisition_id, AcquisitionStatus::Released);
        self.commits
            .insert(attempt.idempotency_key.clone(), (attempt, record.clone()));
        self.advance(now_millis);
        Ok(record)
    }

    /// Deterministically applies expiry/timeout and grants the oldest eligible
    /// waiter. Calling this operation repeatedly at the same time is stable.
    pub fn advance(&mut self, now_millis: u64) {
        if self
            .active
            .as_ref()
            .is_some_and(|ticket| now_millis >= ticket.expires_at_millis)
        {
            let expired = self.active.take().expect("expired active ticket");
            self.acquisitions
                .insert(expired.acquisition_id, AcquisitionStatus::Fenced);
        }
        let mut waiting = VecDeque::with_capacity(self.waiters.len());
        for waiter in self.waiters.drain(..) {
            if now_millis >= waiter.deadline_millis {
                self.acquisitions
                    .insert(waiter.acquisition_id, AcquisitionStatus::TimedOut);
            } else {
                waiting.push_back(waiter);
            }
        }
        self.waiters = waiting;
        while self.active.is_none() {
            let Some(waiter) = self.waiters.pop_front() else {
                break;
            };
            if waiter.base_snapshot_cid != self.head_snapshot_cid
                || waiter.base_generation != self.head_generation
            {
                let status = self.stale_status();
                self.acquisitions.insert(waiter.acquisition_id, status);
                continue;
            }
            match self.grant(
                waiter.acquisition_id.clone(),
                waiter.holder,
                waiter.base_snapshot_cid,
                waiter.base_generation,
                now_millis,
            ) {
                Ok(ticket) => {
                    self.acquisitions
                        .insert(waiter.acquisition_id, AcquisitionStatus::Granted { ticket });
                }
                Err(_) => {
                    self.acquisitions
                        .insert(waiter.acquisition_id, AcquisitionStatus::Fenced);
                }
            }
        }
        for (position, waiter) in self.waiters.iter().enumerate() {
            self.acquisitions.insert(
                waiter.acquisition_id.clone(),
                AcquisitionStatus::Queued {
                    position: position + 1,
                },
            );
        }
    }

    fn grant(
        &mut self,
        acquisition_id: String,
        holder: String,
        base_snapshot_cid: Cid,
        base_generation: u64,
        now_millis: u64,
    ) -> Result<WriterTicket, SqliteError> {
        let expires_at_millis = now_millis
            .checked_add(self.lease_millis)
            .ok_or_else(|| SqliteError::Invalid("writer lease deadline overflow".into()))?;
        let ticket = WriterTicket {
            ticket_id: format!(
                "{}:{}:{}",
                self.database, self.leader_term, self.next_ticket
            ),
            acquisition_id,
            database: self.database.clone(),
            holder,
            base_snapshot_cid,
            base_generation,
            leader_term: self.leader_term,
            lease_epoch: 1,
            expires_at_millis,
        };
        self.next_ticket = self
            .next_ticket
            .checked_add(1)
            .ok_or_else(|| SqliteError::Invalid("writer ticket sequence overflow".into()))?;
        self.active = Some(ticket.clone());
        Ok(ticket)
    }

    fn validate_active(&self, ticket: &WriterTicket, now_millis: u64) -> Result<(), SqliteError> {
        let Some(active) = &self.active else {
            return Err(SqliteError::Fenced);
        };
        if active != ticket
            || ticket.database != self.database
            || ticket.leader_term != self.leader_term
            || now_millis >= ticket.expires_at_millis
        {
            return Err(SqliteError::Fenced);
        }
        Ok(())
    }

    fn stale_status(&self) -> AcquisitionStatus {
        AcquisitionStatus::Stale {
            current_snapshot_cid: self.head_snapshot_cid.clone(),
            current_generation: self.head_generation,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(marker: u8) -> Cid {
        Cid::new(CODEC_SQLITE_SNAPSHOT, &[marker])
    }

    fn coordinator() -> WriterCoordinator {
        WriterCoordinator::new("db", snapshot(1), 7, 11, 100, 4).unwrap()
    }

    fn granted(status: AcquisitionStatus) -> WriterTicket {
        match status {
            AcquisitionStatus::Granted { ticket } => ticket,
            other => panic!("expected granted ticket, got {other:?}"),
        }
    }

    #[test]
    fn acquire_release_and_fifo_waiting_are_deterministic() {
        let mut state = coordinator();
        let first = granted(state.acquire("a", "one", snapshot(1), 7, 0, 0).unwrap());
        assert_eq!(
            state.acquire("b", "two", snapshot(1), 7, 1, 50).unwrap(),
            AcquisitionStatus::Queued { position: 1 }
        );
        state.release(&first, 2).unwrap();
        assert!(matches!(
            state.acquisition_status("b"),
            Some(AcquisitionStatus::Granted { .. })
        ));
    }

    #[test]
    fn timeout_disconnect_and_expiry_release_the_writer() {
        let mut state = coordinator();
        let first = granted(state.acquire("a", "one", snapshot(1), 7, 0, 0).unwrap());
        state.acquire("b", "two", snapshot(1), 7, 1, 5).unwrap();
        state.advance(6);
        assert_eq!(
            state.acquisition_status("b"),
            Some(&AcquisitionStatus::TimedOut)
        );
        state.disconnect("one", 7);
        assert!(state.active_ticket().is_none());
        assert!(matches!(state.renew(&first, 7), Err(SqliteError::Fenced)));

        let second = granted(state.acquire("c", "three", snapshot(1), 7, 8, 0).unwrap());
        state.advance(second.expires_at_millis);
        assert!(state.active_ticket().is_none());
        assert_eq!(
            state.acquisition_status("c"),
            Some(&AcquisitionStatus::Fenced)
        );
    }

    #[test]
    fn renewal_changes_epoch_and_fences_old_ticket() {
        let mut state = coordinator();
        let old = granted(state.acquire("a", "one", snapshot(1), 7, 0, 0).unwrap());
        let renewed = state.renew(&old, 50).unwrap();
        assert_eq!(renewed.lease_epoch, 2);
        assert_eq!(renewed.expires_at_millis, 150);
        assert!(matches!(state.release(&old, 60), Err(SqliteError::Fenced)));
        state.release(&renewed, 60).unwrap();
    }

    #[test]
    fn leader_term_change_fences_active_and_waiting_tickets() {
        let mut state = coordinator();
        let old = granted(state.acquire("a", "one", snapshot(1), 7, 0, 0).unwrap());
        state.acquire("b", "two", snapshot(1), 7, 1, 50).unwrap();
        state.change_leader_term(12, 2).unwrap();
        assert_eq!(
            state.acquisition_status("a"),
            Some(&AcquisitionStatus::Fenced)
        );
        assert_eq!(
            state.acquisition_status("b"),
            Some(&AcquisitionStatus::Fenced)
        );
        assert!(matches!(state.release(&old, 3), Err(SqliteError::Fenced)));
    }

    #[test]
    fn stale_read_to_write_upgrade_is_rejected() {
        let mut state = coordinator();
        assert!(matches!(
            state.acquire("a", "one", snapshot(9), 6, 0, 0).unwrap(),
            AcquisitionStatus::Stale {
                current_generation: 7,
                ..
            }
        ));
    }

    #[test]
    fn exact_head_fence_and_idempotency_make_commit_linearizable() {
        let mut state = coordinator();
        let ticket = granted(state.acquire("a", "one", snapshot(1), 7, 0, 0).unwrap());
        let attempt = CommitAttempt {
            idempotency_key: "commit-a".into(),
            ticket,
            base_snapshot_cid: snapshot(1),
            base_generation: 7,
            new_snapshot_cid: snapshot(2),
        };
        let committed = state.guarded_commit(attempt.clone(), 1).unwrap();
        assert_eq!(committed.generation, 8);
        assert_eq!(state.head(), (&snapshot(2), 8));

        // Simulates a response lost after quorum: replay resolves to the same
        // durable record even though the writer ticket has been released.
        assert_eq!(state.guarded_commit(attempt, 2).unwrap(), committed);
        assert_eq!(state.commit_status("commit-a"), Some(&committed));

        let next = granted(state.acquire("b", "two", snapshot(2), 8, 3, 0).unwrap());
        let stale = CommitAttempt {
            idempotency_key: "commit-b".into(),
            ticket: next,
            base_snapshot_cid: snapshot(1),
            base_generation: 7,
            new_snapshot_cid: snapshot(3),
        };
        assert!(matches!(
            state.guarded_commit(stale, 4),
            Err(SqliteError::GenerationConflict {
                current_generation: 8
            })
        ));
    }
}
