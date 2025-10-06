// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Health check response
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub timestamp: DateTime<Utc>,
    pub version: String,
    pub vault_connected: bool,
}

/// Transaction execution request
#[derive(Debug, Deserialize)]
pub struct ExecuteTransactionRequest {
    /// Target address to send IOTA to (optional, defaults to predefined address)
    pub target_address: Option<String>,
    /// Amount to transfer in MIST (optional, defaults to 0.005 IOTA = 5,000,000 MIST)
    pub amount: Option<u64>,
    /// Optional description for the transaction
    pub description: Option<String>,
}

/// Transaction execution response
#[derive(Debug, Serialize)]
pub struct ExecuteTransactionResponse {
    pub success: bool,
    pub message: String,
    pub transaction_digest: Option<String>,
    pub explorer_url: Option<String>,
    pub key_id: String,
    pub from_address: String,
    pub to_address: String,
    pub amount_mist: u64,
    pub amount_iota: f64,
    pub executed_at: DateTime<Utc>,
}

/// Key information response
#[derive(Debug, Serialize)]
pub struct KeyInfo {
    pub key_id: String,
    pub iota_address: String,
    pub created_at: DateTime<Utc>,
}

/// List keys response
#[derive(Debug, Serialize)]
pub struct ListKeysResponse {
    pub keys: Vec<KeyInfo>,
    pub total: usize,
}