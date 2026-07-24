// SPDX-License-Identifier: Apache-2.0

//! Product-neutral orchestration for prepared-artifact commits.
//!
//! Product adapters own artifact formats, durability policy, guards, proposal
//! semantics, staging persistence, and reconciliation. This crate owns the
//! ordering of those transitions and the ambiguous-result recovery rule.

use async_trait::async_trait;
use futures_util::{StreamExt, stream};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

static PREPARED: AtomicU64 = AtomicU64::new(0);
static STAGED: AtomicU64 = AtomicU64::new(0);
static DURABLE: AtomicU64 = AtomicU64::new(0);
static PROPOSED: AtomicU64 = AtomicU64::new(0);
static AMBIGUOUS: AtomicU64 = AtomicU64::new(0);
static RECOVERED: AtomicU64 = AtomicU64::new(0);
static RECONCILED: AtomicU64 = AtomicU64::new(0);
static FINALIZED: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CommitStats {
    pub prepared: u64,
    pub staged: u64,
    pub durable: u64,
    pub proposed: u64,
    pub ambiguous: u64,
    pub recovered: u64,
    pub reconciled: u64,
    pub finalized: u64,
}

pub fn process_stats() -> CommitStats {
    CommitStats {
        prepared: PREPARED.load(Ordering::Relaxed),
        staged: STAGED.load(Ordering::Relaxed),
        durable: DURABLE.load(Ordering::Relaxed),
        proposed: PROPOSED.load(Ordering::Relaxed),
        ambiguous: AMBIGUOUS.load(Ordering::Relaxed),
        recovered: RECOVERED.load(Ordering::Relaxed),
        reconciled: RECONCILED.load(Ordering::Relaxed),
        finalized: FINALIZED.load(Ordering::Relaxed),
    }
}

/// Closed transition boundaries for deterministic fault injection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CommitStage {
    PrepareBefore,
    PrepareAfter,
    StageBefore,
    StageAfter,
    DurabilityBefore,
    DurabilityAfter,
    ProposalBefore,
    ProposalAfter,
    AmbiguousLookupBefore,
    AmbiguousLookupAfter,
    ReconcileBefore,
    ReconcileAfter,
    FinalizeBefore,
    FinalizeAfter,
}

pub trait CommitFaultInjector<E>: Send + Sync + 'static {
    fn hit(&self, stage: CommitStage) -> Result<(), E>;
}

/// One product's concrete types. None of these types may require another
/// product's API or wire representation.
pub trait CommitTypes: Send + Sync {
    type Request: Send + Sync;
    type Prepared: Send;
    type Evidence: Send + Sync;
    type Guard: Send + Sync;
    type Proposal: Send;
    type Result: Send + Sync;
    type Error: Send + 'static;
}

/// Builds immutable product artifacts and the staging description without
/// publishing authoritative state.
#[async_trait]
pub trait ArtifactPreparer: CommitTypes {
    async fn prepare(&self, request: &Self::Request) -> Result<Self::Prepared, Self::Error>;
}

/// Persists and protects temporary staging state. Finalization occurs after a
/// clear rejection or after the safe success/reconciliation boundary.
#[async_trait]
pub trait StagingBackend: CommitTypes {
    async fn stage(
        &self,
        request: &Self::Request,
        prepared: &mut Self::Prepared,
    ) -> Result<(), Self::Error>;

    async fn finalize(
        &self,
        request: &Self::Request,
        prepared: &mut Self::Prepared,
        disposition: CommitDisposition,
    ) -> Result<(), Self::Error>;
}

/// Establishes and returns trusted durability evidence for prepared artifacts.
#[async_trait]
pub trait DurabilityEstablisher: CommitTypes {
    async fn establish(
        &self,
        request: &Self::Request,
        prepared: &mut Self::Prepared,
    ) -> Result<Self::Evidence, Self::Error>;
}

/// Distinguishes a known proposal response from an outcome that may have
/// committed but whose response was lost.
#[derive(Debug)]
pub enum ProposalAttempt<P, E> {
    Definitive(P),
    Ambiguous(E),
}

/// Validates the product guard at authoritative order and proposes only the
/// small state transition. Product payload bytes stay in `Prepared`.
#[async_trait]
pub trait GuardedProposer: CommitTypes {
    async fn propose(
        &self,
        request: &Self::Request,
        prepared: &Self::Prepared,
        evidence: &Self::Evidence,
        guard: &Self::Guard,
    ) -> ProposalAttempt<Self::Proposal, Self::Error>;

    fn interpret(&self, proposal: Self::Proposal) -> Result<Self::Result, Self::Error>;
}

/// Looks up an idempotent result only after an ambiguous proposal outcome.
/// The ordinary successful path never calls this trait.
#[async_trait]
pub trait ResultLookup: CommitTypes {
    async fn lookup(
        &self,
        request: &Self::Request,
        prepared: &Self::Prepared,
    ) -> Result<Option<Self::Result>, Self::Error>;
}

/// Establishes permanent lifecycle/retention state before temporary staging
/// protection may be removed.
#[async_trait]
pub trait CommitReconciler: CommitTypes {
    async fn reconcile(
        &self,
        request: &Self::Request,
        prepared: &Self::Prepared,
        evidence: &Self::Evidence,
        result: &Self::Result,
    ) -> Result<(), Self::Error>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitDisposition {
    Committed,
    Rejected,
    AmbiguousUnresolved,
}

#[derive(Debug)]
pub struct CommitInput<R, G> {
    pub request: R,
    pub guard: G,
}

#[derive(Debug)]
pub struct CommitOutcome<R, E> {
    pub result: R,
    pub evidence: E,
    pub ambiguous_recovered: bool,
}

/// Stateless orchestration over a product workflow. It adds no persistence
/// barrier or authoritative read to the ordinary success path.
pub struct CommitEngine<W: CommitTypes> {
    workflow: W,
    faults: Option<Arc<dyn CommitFaultInjector<W::Error>>>,
}

impl<W: CommitTypes> CommitEngine<W> {
    pub fn new(workflow: W) -> Self {
        Self {
            workflow,
            faults: None,
        }
    }

    pub fn with_fault_injector(mut self, faults: Arc<dyn CommitFaultInjector<W::Error>>) -> Self {
        self.faults = Some(faults);
        self
    }

    pub fn workflow(&self) -> &W {
        &self.workflow
    }

    fn fault(&self, stage: CommitStage) -> Result<(), W::Error> {
        match &self.faults {
            Some(faults) => faults.hit(stage),
            None => Ok(()),
        }
    }
}

impl<W> CommitEngine<W>
where
    W: ArtifactPreparer
        + StagingBackend
        + DurabilityEstablisher
        + GuardedProposer
        + ResultLookup
        + CommitReconciler,
{
    pub async fn execute(
        &self,
        input: CommitInput<W::Request, W::Guard>,
    ) -> Result<CommitOutcome<W::Result, W::Evidence>, W::Error> {
        let CommitInput { request, guard } = input;
        self.fault(CommitStage::PrepareBefore)?;
        let mut prepared = self.workflow.prepare(&request).await?;
        PREPARED.fetch_add(1, Ordering::Relaxed);
        self.fault(CommitStage::PrepareAfter)?;

        self.fault(CommitStage::StageBefore)?;
        self.workflow.stage(&request, &mut prepared).await?;
        STAGED.fetch_add(1, Ordering::Relaxed);
        if let Err(error) = self.fault(CommitStage::StageAfter) {
            self.finalize_failure(&request, &mut prepared, CommitDisposition::Rejected)
                .await?;
            return Err(error);
        }

        if let Err(error) = self.fault(CommitStage::DurabilityBefore) {
            self.finalize_failure(&request, &mut prepared, CommitDisposition::Rejected)
                .await?;
            return Err(error);
        }
        let evidence = match self.workflow.establish(&request, &mut prepared).await {
            Ok(evidence) => evidence,
            Err(error) => {
                self.finalize_failure(&request, &mut prepared, CommitDisposition::Rejected)
                    .await?;
                return Err(error);
            }
        };
        DURABLE.fetch_add(1, Ordering::Relaxed);
        if let Err(error) = self.fault(CommitStage::DurabilityAfter) {
            self.finalize_failure(&request, &mut prepared, CommitDisposition::Rejected)
                .await?;
            return Err(error);
        }

        if let Err(error) = self.fault(CommitStage::ProposalBefore) {
            self.finalize_failure(&request, &mut prepared, CommitDisposition::Rejected)
                .await?;
            return Err(error);
        }
        let attempt = self
            .workflow
            .propose(&request, &prepared, &evidence, &guard)
            .await;
        PROPOSED.fetch_add(1, Ordering::Relaxed);

        let (result, ambiguous_recovered) = match attempt {
            ProposalAttempt::Definitive(proposal) => {
                if let Err(error) = self.fault(CommitStage::ProposalAfter) {
                    self.recover_ambiguous(&request, &mut prepared, error)
                        .await?
                } else {
                    match self.workflow.interpret(proposal) {
                        Ok(result) => (result, false),
                        Err(error) => {
                            self.finalize_failure(
                                &request,
                                &mut prepared,
                                CommitDisposition::Rejected,
                            )
                            .await?;
                            return Err(error);
                        }
                    }
                }
            }
            ProposalAttempt::Ambiguous(error) => {
                self.recover_ambiguous(&request, &mut prepared, error)
                    .await?
            }
        };

        self.fault(CommitStage::ReconcileBefore)?;
        self.workflow
            .reconcile(&request, &prepared, &evidence, &result)
            .await?;
        RECONCILED.fetch_add(1, Ordering::Relaxed);
        self.fault(CommitStage::ReconcileAfter)?;

        self.fault(CommitStage::FinalizeBefore)?;
        self.workflow
            .finalize(&request, &mut prepared, CommitDisposition::Committed)
            .await?;
        FINALIZED.fetch_add(1, Ordering::Relaxed);
        self.fault(CommitStage::FinalizeAfter)?;
        Ok(CommitOutcome {
            result,
            evidence,
            ambiguous_recovered,
        })
    }

    /// Runs independent commits concurrently up to `max_in_flight`. A product
    /// proposer may combine the resulting concurrent proposals into one
    /// downstream batch without coupling artifact or durability work.
    pub async fn execute_batch(
        &self,
        inputs: Vec<CommitInput<W::Request, W::Guard>>,
        max_in_flight: usize,
    ) -> Vec<Result<CommitOutcome<W::Result, W::Evidence>, W::Error>> {
        let limit = max_in_flight.max(1);
        stream::iter(inputs.into_iter().map(|input| self.execute(input)))
            .buffered(limit)
            .collect()
            .await
    }

    async fn recover_ambiguous(
        &self,
        request: &W::Request,
        prepared: &mut W::Prepared,
        original: W::Error,
    ) -> Result<(W::Result, bool), W::Error> {
        AMBIGUOUS.fetch_add(1, Ordering::Relaxed);
        // Staging remains protected because the proposal may have committed.
        self.fault(CommitStage::AmbiguousLookupBefore)?;
        let result = self.workflow.lookup(request, prepared).await?;
        self.fault(CommitStage::AmbiguousLookupAfter)?;
        match result {
            Some(result) => {
                RECOVERED.fetch_add(1, Ordering::Relaxed);
                Ok((result, true))
            }
            None => {
                self.finalize_failure(request, prepared, CommitDisposition::AmbiguousUnresolved)
                    .await?;
                Err(original)
            }
        }
    }

    async fn finalize_failure(
        &self,
        request: &W::Request,
        prepared: &mut W::Prepared,
        disposition: CommitDisposition,
    ) -> Result<(), W::Error> {
        self.fault(CommitStage::FinalizeBefore)?;
        self.workflow
            .finalize(request, prepared, disposition)
            .await?;
        FINALIZED.fetch_add(1, Ordering::Relaxed);
        self.fault(CommitStage::FinalizeAfter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::HashMap,
        sync::{
            Mutex,
            atomic::{AtomicUsize, Ordering as AtomicOrdering},
        },
        time::Duration,
    };

    #[derive(Clone)]
    struct MockWorkflow {
        state: Arc<Mutex<MockState>>,
        ambiguous: bool,
        active: Arc<AtomicUsize>,
        max_active: Arc<AtomicUsize>,
    }

    #[derive(Default)]
    struct MockState {
        staged: HashMap<u64, bool>,
        results: HashMap<u64, u64>,
        lookups: usize,
        reconciled: Vec<u64>,
        finalized: Vec<(u64, CommitDisposition)>,
    }

    impl CommitTypes for MockWorkflow {
        type Request = u64;
        type Prepared = u64;
        type Evidence = u64;
        type Guard = u64;
        type Proposal = u64;
        type Result = u64;
        type Error = &'static str;
    }

    #[async_trait]
    impl ArtifactPreparer for MockWorkflow {
        async fn prepare(&self, request: &u64) -> Result<u64, &'static str> {
            Ok(*request)
        }
    }

    #[async_trait]
    impl StagingBackend for MockWorkflow {
        async fn stage(&self, request: &u64, _prepared: &mut u64) -> Result<(), &'static str> {
            self.state.lock().unwrap().staged.insert(*request, true);
            Ok(())
        }

        async fn finalize(
            &self,
            request: &u64,
            _prepared: &mut u64,
            disposition: CommitDisposition,
        ) -> Result<(), &'static str> {
            let mut state = self.state.lock().unwrap();
            state.staged.insert(*request, false);
            state.finalized.push((*request, disposition));
            Ok(())
        }
    }

    #[async_trait]
    impl DurabilityEstablisher for MockWorkflow {
        async fn establish(&self, request: &u64, _prepared: &mut u64) -> Result<u64, &'static str> {
            Ok(request + 10)
        }
    }

    #[async_trait]
    impl GuardedProposer for MockWorkflow {
        async fn propose(
            &self,
            request: &u64,
            _prepared: &u64,
            evidence: &u64,
            guard: &u64,
        ) -> ProposalAttempt<u64, &'static str> {
            let active = self.active.fetch_add(1, AtomicOrdering::AcqRel) + 1;
            self.max_active.fetch_max(active, AtomicOrdering::AcqRel);
            tokio::time::sleep(Duration::from_millis(10)).await;
            self.active.fetch_sub(1, AtomicOrdering::AcqRel);
            let result = request + evidence + guard;
            self.state.lock().unwrap().results.insert(*request, result);
            if self.ambiguous {
                ProposalAttempt::Ambiguous("response lost")
            } else {
                ProposalAttempt::Definitive(result)
            }
        }

        fn interpret(&self, proposal: u64) -> Result<u64, &'static str> {
            Ok(proposal)
        }
    }

    #[async_trait]
    impl ResultLookup for MockWorkflow {
        async fn lookup(
            &self,
            request: &u64,
            _prepared: &u64,
        ) -> Result<Option<u64>, &'static str> {
            let mut state = self.state.lock().unwrap();
            state.lookups += 1;
            Ok(state.results.get(request).copied())
        }
    }

    #[async_trait]
    impl CommitReconciler for MockWorkflow {
        async fn reconcile(
            &self,
            request: &u64,
            _prepared: &u64,
            _evidence: &u64,
            _result: &u64,
        ) -> Result<(), &'static str> {
            self.state.lock().unwrap().reconciled.push(*request);
            Ok(())
        }
    }

    fn workflow(ambiguous: bool) -> MockWorkflow {
        MockWorkflow {
            state: Arc::new(Mutex::new(MockState::default())),
            ambiguous,
            active: Arc::new(AtomicUsize::new(0)),
            max_active: Arc::new(AtomicUsize::new(0)),
        }
    }

    #[tokio::test]
    async fn ordinary_success_has_no_result_lookup() {
        let workflow = workflow(false);
        let state = workflow.state.clone();
        let outcome = CommitEngine::new(workflow)
            .execute(CommitInput {
                request: 1,
                guard: 2,
            })
            .await
            .unwrap();
        assert_eq!(outcome.result, 14);
        assert!(!outcome.ambiguous_recovered);
        let state = state.lock().unwrap();
        assert_eq!(state.lookups, 0);
        assert_eq!(state.reconciled, vec![1]);
        assert_eq!(state.finalized, vec![(1, CommitDisposition::Committed)]);
    }

    #[tokio::test]
    async fn ambiguous_response_is_reconstructed_before_staging_release() {
        let workflow = workflow(true);
        let state = workflow.state.clone();
        let outcome = CommitEngine::new(workflow)
            .execute(CommitInput {
                request: 7,
                guard: 3,
            })
            .await
            .unwrap();
        assert_eq!(outcome.result, 27);
        assert!(outcome.ambiguous_recovered);
        let state = state.lock().unwrap();
        assert_eq!(state.lookups, 1);
        assert_eq!(state.reconciled, vec![7]);
        assert_eq!(state.staged.get(&7), Some(&false));
    }

    #[tokio::test]
    async fn bounded_batch_limits_concurrency_and_preserves_result_order() {
        let workflow = workflow(false);
        let max_active = workflow.max_active.clone();
        let inputs = (0..8)
            .map(|request| CommitInput { request, guard: 1 })
            .collect();
        let outcomes = CommitEngine::new(workflow).execute_batch(inputs, 2).await;
        assert!(outcomes.iter().all(Result::is_ok));
        assert_eq!(
            outcomes
                .into_iter()
                .map(|outcome| outcome.unwrap().result)
                .collect::<Vec<_>>(),
            (0..8).map(|request| request * 2 + 11).collect::<Vec<_>>()
        );
        assert_eq!(max_active.load(AtomicOrdering::Acquire), 2);
    }

    struct Inject(CommitStage);

    impl CommitFaultInjector<&'static str> for Inject {
        fn hit(&self, stage: CommitStage) -> Result<(), &'static str> {
            if stage == self.0 {
                Err("injected")
            } else {
                Ok(())
            }
        }
    }

    #[tokio::test]
    async fn clear_preproposal_fault_releases_staging() {
        let workflow = workflow(false);
        let state = workflow.state.clone();
        let result = CommitEngine::new(workflow)
            .with_fault_injector(Arc::new(Inject(CommitStage::DurabilityBefore)))
            .execute(CommitInput {
                request: 4,
                guard: 0,
            })
            .await;
        assert_eq!(result.unwrap_err(), "injected");
        assert_eq!(
            state.lock().unwrap().finalized,
            vec![(4, CommitDisposition::Rejected)]
        );
    }

    #[tokio::test]
    async fn every_transition_fault_has_deterministic_retry_behavior() {
        let stages = [
            CommitStage::PrepareBefore,
            CommitStage::PrepareAfter,
            CommitStage::StageBefore,
            CommitStage::StageAfter,
            CommitStage::DurabilityBefore,
            CommitStage::DurabilityAfter,
            CommitStage::ProposalBefore,
            CommitStage::ProposalAfter,
            CommitStage::ReconcileBefore,
            CommitStage::ReconcileAfter,
            CommitStage::FinalizeBefore,
            CommitStage::FinalizeAfter,
        ];
        for (index, stage) in stages.into_iter().enumerate() {
            let workflow = workflow(false);
            let first = CommitEngine::new(workflow.clone())
                .with_fault_injector(Arc::new(Inject(stage)))
                .execute(CommitInput {
                    request: 100 + index as u64,
                    guard: 0,
                })
                .await;
            if stage == CommitStage::ProposalAfter {
                assert!(
                    first.unwrap().ambiguous_recovered,
                    "post-proposal fault must reconstruct its result"
                );
            } else {
                assert_eq!(first.unwrap_err(), "injected", "stage {stage:?}");
            }
            let retry = CommitEngine::new(workflow)
                .execute(CommitInput {
                    request: 100 + index as u64,
                    guard: 0,
                })
                .await;
            assert!(retry.is_ok(), "retry failed after {stage:?}: {retry:?}");
        }

        for stage in [
            CommitStage::AmbiguousLookupBefore,
            CommitStage::AmbiguousLookupAfter,
        ] {
            let workflow = workflow(true);
            let first = CommitEngine::new(workflow.clone())
                .with_fault_injector(Arc::new(Inject(stage)))
                .execute(CommitInput {
                    request: 999,
                    guard: 0,
                })
                .await;
            assert_eq!(first.unwrap_err(), "injected");
            assert_eq!(
                workflow.state.lock().unwrap().staged.get(&999),
                Some(&true),
                "ambiguous staging must remain protected at {stage:?}"
            );
            assert!(
                CommitEngine::new(workflow)
                    .execute(CommitInput {
                        request: 999,
                        guard: 0,
                    })
                    .await
                    .is_ok()
            );
        }
    }
}
