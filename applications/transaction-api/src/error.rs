// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

pub type AppResult<T> = Result<T, AppError>;

/// Application error types
#[derive(Error, Debug)]
pub enum AppError {
    #[error("Configuration error: {0}")]
    Configuration(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Vault error: {0}")]
    Vault(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Key not found: {0}")]
    KeyNotFound(String),

    #[error("Transaction failed: {0}")]
    TransactionFailed(String),

    #[error("Service unavailable: {0}")]
    ServiceUnavailable(String),

    #[error("Internal server error: {0}")]
    Internal(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match &self {
            AppError::Configuration(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Configuration error"),
            AppError::Storage(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Storage error"),
            AppError::Vault(_) => (StatusCode::BAD_GATEWAY, "Vault service error"),
            AppError::Serialization(_) => (StatusCode::BAD_REQUEST, "Invalid JSON"),
            AppError::Io(_) => (StatusCode::INTERNAL_SERVER_ERROR, "I/O error"),
            AppError::InvalidRequest(_) => (StatusCode::BAD_REQUEST, "Invalid request"),
            AppError::KeyNotFound(_) => (StatusCode::NOT_FOUND, "Key not found"),
            AppError::TransactionFailed(_) => (StatusCode::UNPROCESSABLE_ENTITY, "Transaction failed"),
            AppError::ServiceUnavailable(_) => (StatusCode::SERVICE_UNAVAILABLE, "Service unavailable"),
            AppError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error"),
        };

        let body = Json(json!({
            "error": error_message,
            "message": self.to_string(),
            "status": status.as_u16()
        }));

        (status, body).into_response()
    }
}