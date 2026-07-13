// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    time::{Duration, Instant},
};

pub const DEFAULT_MAX_HISTORY: usize = 64;
pub const DEFAULT_MAX_SEARCH_STATES: usize = 1_000_000;
pub const DEFAULT_CHECK_DEADLINE: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ModelValue {
    pub cid: String,
    pub generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Precondition {
    Any,
    Absent,
    Generation(u64),
    Cid(String),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Mutation {
    Put {
        key: String,
        cid: String,
        precondition: Precondition,
    },
    Delete {
        key: String,
        precondition: Precondition,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum KvOperation {
    Get {
        key: String,
    },
    Mutate {
        request_id: String,
        mutations: Vec<Mutation>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum KvResult {
    Read { value: Option<ModelValue> },
    Committed { revision: u64, replayed: bool },
    Conflict,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryOperation {
    pub id: String,
    pub client_id: String,
    pub invoked_ns: u64,
    pub completed_ns: u64,
    pub operation: KvOperation,
    pub result: KvResult,
    #[serde(default)]
    pub explicitly_stale: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinearizabilityReport {
    pub checked_operations: usize,
    pub excluded_stale_operations: usize,
    pub explored_states: usize,
    pub linearization: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinearizabilityFailure {
    pub reason: String,
    pub checked_operations: usize,
    pub explored_states: usize,
    pub counterexample: Vec<HistoryOperation>,
}

#[derive(Debug, Clone)]
pub struct CheckerLimits {
    pub max_history: usize,
    pub max_search_states: usize,
    pub deadline: Duration,
}

impl Default for CheckerLimits {
    fn default() -> Self {
        Self {
            max_history: DEFAULT_MAX_HISTORY,
            max_search_states: DEFAULT_MAX_SEARCH_STATES,
            deadline: DEFAULT_CHECK_DEADLINE,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Serialize)]
struct ModelState {
    revision: u64,
    values: BTreeMap<String, ModelValue>,
    idempotency: BTreeMap<String, IdempotencyRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
struct IdempotencyRecord {
    mutations: Vec<Mutation>,
    revision: u64,
}

pub fn check_linearizable(
    history: &[HistoryOperation],
    limits: &CheckerLimits,
) -> Result<LinearizabilityReport, LinearizabilityFailure> {
    let excluded_stale_operations = history
        .iter()
        .filter(|operation| operation.explicitly_stale)
        .count();
    let operations = history
        .iter()
        .filter(|operation| !operation.explicitly_stale)
        .cloned()
        .collect::<Vec<_>>();
    if operations.len() > limits.max_history || operations.len() > 120 {
        return Err(LinearizabilityFailure {
            reason: format!(
                "history contains {} operations; bound is {}",
                operations.len(),
                limits.max_history.min(120)
            ),
            checked_operations: operations.len(),
            explored_states: 0,
            counterexample: operations,
        });
    }
    if let Some(operation) = operations
        .iter()
        .find(|operation| operation.completed_ns < operation.invoked_ns)
    {
        return Err(LinearizabilityFailure {
            reason: format!("operation {} completed before invocation", operation.id),
            checked_operations: operations.len(),
            explored_states: 0,
            counterexample: vec![operation.clone()],
        });
    }
    let search = search(&operations, limits);
    match search {
        SearchResult::Accepted { order, explored } => Ok(LinearizabilityReport {
            checked_operations: operations.len(),
            excluded_stale_operations,
            explored_states: explored,
            linearization: order
                .into_iter()
                .map(|index| operations[index].id.clone())
                .collect(),
        }),
        SearchResult::Rejected { reason, explored } => {
            let minimized = minimize_counterexample(operations, limits);
            Err(LinearizabilityFailure {
                reason,
                checked_operations: history.len() - excluded_stale_operations,
                explored_states: explored,
                counterexample: minimized,
            })
        }
    }
}

enum SearchResult {
    Accepted { order: Vec<usize>, explored: usize },
    Rejected { reason: String, explored: usize },
}

fn search(operations: &[HistoryOperation], limits: &CheckerLimits) -> SearchResult {
    let mut predecessors = vec![0u128; operations.len()];
    for (right_index, right) in operations.iter().enumerate() {
        for (left_index, left) in operations.iter().enumerate() {
            if left.completed_ns < right.invoked_ns {
                predecessors[right_index] |= 1u128 << left_index;
            }
        }
    }
    let target = if operations.is_empty() {
        0
    } else {
        (1u128 << operations.len()) - 1
    };
    let started = Instant::now();
    let mut explored = 0usize;
    let mut memo = HashSet::new();
    let mut order = Vec::with_capacity(operations.len());
    let context = SearchContext {
        operations,
        predecessors: &predecessors,
        target,
        limits,
        started,
    };
    match dfs(
        &context,
        0,
        &ModelState::default(),
        &mut order,
        &mut explored,
        &mut memo,
    ) {
        DfsResult::Accepted => SearchResult::Accepted { order, explored },
        DfsResult::Rejected => SearchResult::Rejected {
            reason: "no legal linearization satisfies real-time order and observed results".into(),
            explored,
        },
        DfsResult::Bound(reason) => SearchResult::Rejected { reason, explored },
    }
}

struct SearchContext<'a> {
    operations: &'a [HistoryOperation],
    predecessors: &'a [u128],
    target: u128,
    limits: &'a CheckerLimits,
    started: Instant,
}

enum DfsResult {
    Accepted,
    Rejected,
    Bound(String),
}

fn dfs(
    context: &SearchContext<'_>,
    done: u128,
    state: &ModelState,
    order: &mut Vec<usize>,
    explored: &mut usize,
    memo: &mut HashSet<(u128, [u8; 32])>,
) -> DfsResult {
    if done == context.target {
        return DfsResult::Accepted;
    }
    *explored += 1;
    if *explored > context.limits.max_search_states {
        return DfsResult::Bound(format!(
            "checker exceeded {} search states",
            context.limits.max_search_states
        ));
    }
    if context.started.elapsed() > context.limits.deadline {
        return DfsResult::Bound(format!(
            "checker exceeded {} ms deadline",
            context.limits.deadline.as_millis()
        ));
    }
    let state_bytes = serde_json::to_vec(state).expect("model state serializes");
    let key = (done, *blake3::hash(&state_bytes).as_bytes());
    if !memo.insert(key) {
        return DfsResult::Rejected;
    }
    for index in 0..context.operations.len() {
        let bit = 1u128 << index;
        if done & bit != 0 || context.predecessors[index] & !done != 0 {
            continue;
        }
        for next in apply_states(state, &context.operations[index]) {
            order.push(index);
            match dfs(context, done | bit, &next, order, explored, memo) {
                DfsResult::Accepted => return DfsResult::Accepted,
                DfsResult::Bound(reason) => {
                    order.pop();
                    return DfsResult::Bound(reason);
                }
                DfsResult::Rejected => {
                    order.pop();
                }
            }
        }
    }
    DfsResult::Rejected
}

fn apply_states(state: &ModelState, operation: &HistoryOperation) -> Vec<ModelState> {
    match (&operation.operation, &operation.result) {
        (
            KvOperation::Mutate {
                request_id,
                mutations,
            },
            KvResult::Failed,
        ) => {
            let mut states = vec![state.clone()];
            let conditions_hold = mutations.iter().all(|mutation| match mutation {
                Mutation::Put {
                    key, precondition, ..
                }
                | Mutation::Delete { key, precondition } => {
                    matches_precondition(state.values.get(key), precondition)
                }
            });
            if !state.idempotency.contains_key(request_id)
                && conditions_hold
                && let Some(committed) =
                    commit_mutations(state, request_id, mutations, state.revision + 1)
            {
                states.push(committed);
            }
            states
        }
        (_, KvResult::Failed) => vec![state.clone()],
        (KvOperation::Get { key }, KvResult::Read { value }) => (state.values.get(key)
            == value.as_ref())
        .then(|| state.clone())
        .into_iter()
        .collect(),
        (
            KvOperation::Mutate {
                request_id,
                mutations,
            },
            result,
        ) => apply_mutation(state, request_id, mutations, result)
            .into_iter()
            .collect(),
        _ => Vec::new(),
    }
}

fn apply_mutation(
    state: &ModelState,
    request_id: &str,
    mutations: &[Mutation],
    result: &KvResult,
) -> Option<ModelState> {
    if mutations.is_empty() {
        return None;
    }
    if let Some(previous) = state.idempotency.get(request_id) {
        return match result {
            KvResult::Committed { revision, replayed }
                if previous.mutations == mutations
                    && previous.revision == *revision
                    && *replayed =>
            {
                Some(state.clone())
            }
            KvResult::Conflict if previous.mutations != mutations => Some(state.clone()),
            _ => None,
        };
    }
    let conditions_hold = mutations.iter().all(|mutation| match mutation {
        Mutation::Put {
            key, precondition, ..
        }
        | Mutation::Delete { key, precondition } => {
            matches_precondition(state.values.get(key), precondition)
        }
    });
    match result {
        KvResult::Conflict if !conditions_hold => Some(state.clone()),
        KvResult::Committed {
            revision,
            replayed: false,
        } if conditions_hold && *revision == state.revision + 1 => {
            commit_mutations(state, request_id, mutations, *revision)
        }
        _ => None,
    }
}

fn commit_mutations(
    state: &ModelState,
    request_id: &str,
    mutations: &[Mutation],
    revision: u64,
) -> Option<ModelState> {
    if mutations.is_empty() {
        return None;
    }
    let mut next = state.clone();
    next.revision = revision;
    for mutation in mutations {
        match mutation {
            Mutation::Put { key, cid, .. } => {
                let generation = next.values.get(key).map_or(1, |value| value.generation + 1);
                next.values.insert(
                    key.clone(),
                    ModelValue {
                        cid: cid.clone(),
                        generation,
                    },
                );
            }
            Mutation::Delete { key, .. } => {
                next.values.remove(key);
            }
        }
    }
    next.idempotency.insert(
        request_id.to_string(),
        IdempotencyRecord {
            mutations: mutations.to_vec(),
            revision,
        },
    );
    Some(next)
}

fn matches_precondition(value: Option<&ModelValue>, precondition: &Precondition) -> bool {
    match precondition {
        Precondition::Any => true,
        Precondition::Absent => value.is_none(),
        Precondition::Generation(generation) => {
            value.is_some_and(|value| value.generation == *generation)
        }
        Precondition::Cid(cid) => value.is_some_and(|value| value.cid == *cid),
    }
}

fn minimize_counterexample(
    mut operations: Vec<HistoryOperation>,
    limits: &CheckerLimits,
) -> Vec<HistoryOperation> {
    let deadline = Instant::now() + limits.deadline.min(Duration::from_secs(2));
    let mut index = 0usize;
    while index < operations.len() && Instant::now() < deadline {
        let mut candidate = operations.clone();
        candidate.remove(index);
        if !candidate.is_empty()
            && matches!(search(&candidate, limits), SearchResult::Rejected { .. })
        {
            operations = candidate;
        } else {
            index += 1;
        }
    }
    operations
}

pub fn validate_history_ids(history: &[HistoryOperation]) -> Result<(), String> {
    let mut ids = BTreeSet::new();
    for operation in history {
        if operation.id.is_empty() || !ids.insert(&operation.id) {
            return Err(format!(
                "history operation ID is empty or duplicated: {}",
                operation.id
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn op(
        id: &str,
        invoke: u64,
        complete: u64,
        operation: KvOperation,
        result: KvResult,
    ) -> HistoryOperation {
        HistoryOperation {
            id: id.into(),
            client_id: "client".into(),
            invoked_ns: invoke,
            completed_ns: complete,
            operation,
            result,
            explicitly_stale: false,
        }
    }

    #[test]
    fn accepts_concurrent_put_get_delete_transaction_and_retry() {
        let put = Mutation::Put {
            key: "a".into(),
            cid: "cid-a".into(),
            precondition: Precondition::Absent,
        };
        let transaction = vec![
            Mutation::Put {
                key: "b".into(),
                cid: "cid-b".into(),
                precondition: Precondition::Absent,
            },
            Mutation::Put {
                key: "c".into(),
                cid: "cid-c".into(),
                precondition: Precondition::Absent,
            },
        ];
        let history = vec![
            op(
                "put",
                0,
                4,
                KvOperation::Mutate {
                    request_id: "r1".into(),
                    mutations: vec![put.clone()],
                },
                KvResult::Committed {
                    revision: 1,
                    replayed: false,
                },
            ),
            op(
                "get",
                2,
                6,
                KvOperation::Get { key: "a".into() },
                KvResult::Read {
                    value: Some(ModelValue {
                        cid: "cid-a".into(),
                        generation: 1,
                    }),
                },
            ),
            op(
                "conflict",
                5,
                6,
                KvOperation::Mutate {
                    request_id: "conflict".into(),
                    mutations: vec![put.clone()],
                },
                KvResult::Conflict,
            ),
            op(
                "txn",
                7,
                9,
                KvOperation::Mutate {
                    request_id: "r2".into(),
                    mutations: transaction.clone(),
                },
                KvResult::Committed {
                    revision: 2,
                    replayed: false,
                },
            ),
            op(
                "retry",
                10,
                11,
                KvOperation::Mutate {
                    request_id: "r2".into(),
                    mutations: transaction,
                },
                KvResult::Committed {
                    revision: 2,
                    replayed: true,
                },
            ),
            op(
                "delete",
                12,
                13,
                KvOperation::Mutate {
                    request_id: "r3".into(),
                    mutations: vec![Mutation::Delete {
                        key: "a".into(),
                        precondition: Precondition::Generation(1),
                    }],
                },
                KvResult::Committed {
                    revision: 3,
                    replayed: false,
                },
            ),
        ];
        let report = check_linearizable(&history, &CheckerLimits::default()).unwrap();
        assert_eq!(report.checked_operations, 6);
    }

    #[test]
    fn rejects_and_minimizes_impossible_read() {
        let history = vec![
            op(
                "put",
                0,
                1,
                KvOperation::Mutate {
                    request_id: "r1".into(),
                    mutations: vec![Mutation::Put {
                        key: "a".into(),
                        cid: "new".into(),
                        precondition: Precondition::Absent,
                    }],
                },
                KvResult::Committed {
                    revision: 1,
                    replayed: false,
                },
            ),
            op(
                "bad-read",
                2,
                3,
                KvOperation::Get { key: "a".into() },
                KvResult::Read { value: None },
            ),
            op(
                "unrelated",
                0,
                4,
                KvOperation::Get { key: "z".into() },
                KvResult::Read { value: None },
            ),
        ];
        let failure = check_linearizable(&history, &CheckerLimits::default()).unwrap_err();
        assert!(failure.counterexample.len() <= 2);
        assert!(
            failure
                .counterexample
                .iter()
                .any(|operation| operation.id == "bad-read")
        );
    }

    #[test]
    fn excludes_explicit_stale_reads_and_enforces_bounds() {
        let mut stale = op(
            "stale",
            2,
            3,
            KvOperation::Get { key: "a".into() },
            KvResult::Read {
                value: Some(ModelValue {
                    cid: "old".into(),
                    generation: 0,
                }),
            },
        );
        stale.explicitly_stale = true;
        let report = check_linearizable(&[stale], &CheckerLimits::default()).unwrap();
        assert_eq!(report.excluded_stale_operations, 1);
        let limits = CheckerLimits {
            max_history: 0,
            ..CheckerLimits::default()
        };
        assert!(
            check_linearizable(
                &[op(
                    "get",
                    0,
                    1,
                    KvOperation::Get { key: "a".into() },
                    KvResult::Read { value: None }
                )],
                &limits
            )
            .is_err()
        );
    }

    #[test]
    fn accepts_ambiguous_commit_followed_by_idempotent_replay() {
        let mutations = vec![Mutation::Put {
            key: "a".into(),
            cid: "x".into(),
            precondition: Precondition::Absent,
        }];
        let history = vec![
            op(
                "ambiguous",
                0,
                1,
                KvOperation::Mutate {
                    request_id: "same".into(),
                    mutations: mutations.clone(),
                },
                KvResult::Failed,
            ),
            op(
                "replay",
                2,
                3,
                KvOperation::Mutate {
                    request_id: "same".into(),
                    mutations,
                },
                KvResult::Committed {
                    revision: 1,
                    replayed: true,
                },
            ),
        ];
        assert!(check_linearizable(&history, &CheckerLimits::default()).is_ok());
    }

    #[test]
    fn detects_injected_partial_transaction_visibility() {
        let transaction = vec![
            Mutation::Put {
                key: "a".into(),
                cid: "x".into(),
                precondition: Precondition::Absent,
            },
            Mutation::Put {
                key: "b".into(),
                cid: "y".into(),
                precondition: Precondition::Absent,
            },
        ];
        let history = vec![
            op(
                "transaction",
                0,
                1,
                KvOperation::Mutate {
                    request_id: "txn".into(),
                    mutations: transaction,
                },
                KvResult::Committed {
                    revision: 1,
                    replayed: false,
                },
            ),
            op(
                "read-a",
                2,
                3,
                KvOperation::Get { key: "a".into() },
                KvResult::Read {
                    value: Some(ModelValue {
                        cid: "x".into(),
                        generation: 1,
                    }),
                },
            ),
            op(
                "read-b",
                2,
                3,
                KvOperation::Get { key: "b".into() },
                KvResult::Read { value: None },
            ),
        ];
        assert!(check_linearizable(&history, &CheckerLimits::default()).is_err());
    }

    #[test]
    fn detects_injected_idempotency_violation() {
        let mutation = vec![Mutation::Put {
            key: "a".into(),
            cid: "x".into(),
            precondition: Precondition::Absent,
        }];
        let history = vec![
            op(
                "first",
                0,
                1,
                KvOperation::Mutate {
                    request_id: "same".into(),
                    mutations: mutation.clone(),
                },
                KvResult::Committed {
                    revision: 1,
                    replayed: false,
                },
            ),
            op(
                "duplicate",
                2,
                3,
                KvOperation::Mutate {
                    request_id: "same".into(),
                    mutations: mutation,
                },
                KvResult::Committed {
                    revision: 2,
                    replayed: false,
                },
            ),
        ];
        assert!(check_linearizable(&history, &CheckerLimits::default()).is_err());
    }
}
