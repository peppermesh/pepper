// SPDX-License-Identifier: Apache-2.0

//! Internal immutable-object write boundary.
//!
//! Application services use this API to receive the root and every descendant
//! durability receipt without constructing an Axum request. Streaming HTTP
//! handlers continue to feed the same underlying builders directly.

use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // Configured/EC policies are consumed by the SQLite service in Phase 1.
pub(super) enum ObjectWritePolicy {
    /// Apply the node's small-object and replicated/EC threshold policy.
    Configured,
    /// Force a replicated ordinary object regardless of the EC threshold.
    Replicated,
    /// Force EC with an explicit layout.
    Erasure {
        data_shards: u16,
        parity_shards: u16,
    },
}

#[derive(Clone)]
pub(super) struct ObjectWriteService {
    state: AppState,
}

impl ObjectWriteService {
    pub(super) fn new(state: AppState) -> Self {
        Self { state }
    }

    pub(super) async fn write_bytes(
        &self,
        bytes: Vec<u8>,
        policy: ObjectWritePolicy,
    ) -> Result<ObjectWriteReceipts, ApiError> {
        enforce_size_limit(self.state.max_object_bytes, bytes.len() as u64, "object")?;
        let length = bytes.len() as u64;
        let body = Body::from(bytes);
        match policy {
            ObjectWritePolicy::Configured => {
                put_policy_object_stream_receipts(&self.state, body, Some(length), false).await
            }
            ObjectWritePolicy::Replicated => put_object_stream_receipts(&self.state, body).await,
            ObjectWritePolicy::Erasure {
                data_shards,
                parity_shards,
            } => {
                put_erasure_object_stream_receipts(&self.state, body, data_shards, parity_shards)
                    .await
            }
        }
    }
}
