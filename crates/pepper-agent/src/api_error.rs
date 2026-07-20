// SPDX-License-Identifier: Apache-2.0

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use pepper_dag::DagError;
use pepper_metadata::MetadataError;
use pepper_network::NetworkError;
use pepper_storage::StorageError;
use pepper_types::{ErrorCode, ErrorResponse};

#[derive(Debug)]
pub(super) struct ApiError {
    pub(super) status: StatusCode,
    pub(super) code: ErrorCode,
    pub(super) message: String,
}

impl ApiError {
    pub(super) fn new(status: StatusCode, code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }

    pub(super) fn header(error: axum::http::header::InvalidHeaderValue) -> Self {
        Self::internal(error.to_string())
    }

    pub(super) fn network(error: NetworkError) -> Self {
        Self::from(error)
    }

    pub(super) fn dag(error: DagError) -> Self {
        let code = if matches!(error, DagError::UnsupportedCodec(_)) {
            ErrorCode::UnsupportedCodec
        } else {
            ErrorCode::InvalidRequest
        };
        Self::new(StatusCode::BAD_REQUEST, code, error.to_string())
    }

    pub(super) fn metadata(error: MetadataError) -> Self {
        match error {
            MetadataError::ImmutablePinFields | MetadataError::PinReactivation => {
                Self::bad_request(error.to_string())
            }
            _ => Self::internal(error.to_string()),
        }
    }

    pub(super) fn serde(error: serde_json::Error) -> Self {
        Self::bad_request(error.to_string())
    }

    pub(super) fn manifest(error: pepper_types::ManifestError) -> Self {
        Self::bad_request(error.to_string())
    }

    pub(super) fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, ErrorCode::InvalidRequest, message)
    }

    pub(super) fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, ErrorCode::NotFound, message)
    }

    pub(super) fn internal(message: impl Into<String>) -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            ErrorCode::Internal,
            message,
        )
    }

    pub(super) fn redb_transaction(error: redb::TransactionError) -> Self {
        Self::internal(error.to_string())
    }

    pub(super) fn redb_table(error: redb::TableError) -> Self {
        Self::internal(error.to_string())
    }

    pub(super) fn redb_storage(error: redb::StorageError) -> Self {
        Self::internal(error.to_string())
    }

    pub(super) fn redb_commit(error: redb::CommitError) -> Self {
        Self::internal(error.to_string())
    }
}

impl From<StorageError> for ApiError {
    fn from(error: StorageError) -> Self {
        let (status, code) = match error {
            StorageError::InvalidCid(_) | StorageError::InvalidRange { .. } => {
                (StatusCode::BAD_REQUEST, ErrorCode::InvalidRequest)
            }
            StorageError::NotFound(_) => (StatusCode::NOT_FOUND, ErrorCode::NotFound),
            StorageError::HashMismatch(_) | StorageError::InvalidEncodedBlock(_) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                ErrorCode::IntegrityFailure,
            ),
            StorageError::CapacityExceeded { .. } | StorageError::NoStorageLocations => (
                StatusCode::INSUFFICIENT_STORAGE,
                ErrorCode::CapacityExceeded,
            ),
            StorageError::BlockTooLarge { .. } => {
                (StatusCode::PAYLOAD_TOO_LARGE, ErrorCode::PayloadTooLarge)
            }
            StorageError::LocationLocked(_) | StorageError::LockPoisoned => {
                (StatusCode::SERVICE_UNAVAILABLE, ErrorCode::Unavailable)
            }
            StorageError::Io { .. }
            | StorageError::Transaction(_)
            | StorageError::Table(_)
            | StorageError::RedbStorage(_)
            | StorageError::Commit(_)
            | StorageError::Serde(_)
            | StorageError::BatchResultMissing
            | StorageError::PreverifiedCidMismatch(_)
            | StorageError::Compression(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, ErrorCode::Internal)
            }
        };
        Self::new(status, code, error.to_string())
    }
}

impl From<NetworkError> for ApiError {
    fn from(error: NetworkError) -> Self {
        let (status, code) = match error {
            NetworkError::Rpc { .. } | NetworkError::BlockService(_) => {
                (StatusCode::BAD_GATEWAY, ErrorCode::UpstreamFailure)
            }
            NetworkError::InvalidPeerAddress { .. } | NetworkError::InvalidDescriptor(_) => {
                (StatusCode::BAD_REQUEST, ErrorCode::InvalidRequest)
            }
            NetworkError::UnsupportedMethod(_) => (StatusCode::NOT_FOUND, ErrorCode::NotFound),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, ErrorCode::Internal),
        };
        Self::new(status, code, error.to_string())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = ErrorResponse {
            code: self.code,
            error: self.message,
        };
        (self.status, Json(body)).into_response()
    }
}
