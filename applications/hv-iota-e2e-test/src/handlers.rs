// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use axum::{
    extract::State,
    response::Json,
};
use chrono::Utc;
use tracing::{info, warn};

use crate::{
    error::AppResult,
    models::*,
    AppState,
};

/// Health check endpoint
pub async fn health_check(State(_state): State<AppState>) -> AppResult<Json<HealthResponse>> {
    Ok(Json(HealthResponse {
        status: "healthy".to_string(),
        timestamp: Utc::now(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        vault_connected: true,
    }))
}

/// Execute the full IOTA transaction workflow (equivalent to iota_vault_demo.rs)
pub async fn execute_transaction(
    State(state): State<AppState>,
) -> AppResult<Json<ExecuteTransactionResponse>> {
    info!("🚀 Starting IOTA transaction execution");

    // Static values for testing
    let target_address = "0x1f9699f7b7baee05b2a6eea4eb41bb923fb64732069a1bf010506cd3d2d9ab26".to_string();
    let amount_mist = 5_000_000; // 0.005 IOTA
    let amount_iota = amount_mist as f64 / 1_000_000_000.0;

    info!("📋 Transaction parameters:");
    info!("   To: {}", target_address);
    info!("   Amount: {} MIST ({:.6} IOTA)", amount_mist, amount_iota);

    // Execute the full workflow (this will take time!)
    match state.transaction_service.execute_iota_transaction(
        &target_address,
        amount_mist,
        None
    ).await {
        Ok((transaction_digest, key_id, from_address)) => {
            let explorer_url = format!(
                "https://explorer.iota.org/txblock/{}?network=testnet",
                transaction_digest
            );

            info!("✅ Transaction successful: {}", transaction_digest);

            let response = ExecuteTransactionResponse {
                success: true,
                message: "Transaction executed successfully".to_string(),
                transaction_digest: Some(transaction_digest),
                explorer_url: Some(explorer_url),
                key_id,
                from_address,
                to_address: target_address,
                amount_mist,
                amount_iota,
                executed_at: Utc::now(),
            };

            Ok(Json(response))
        }
        Err(e) => {
            warn!("❌ Transaction failed: {}", e);

            let response = ExecuteTransactionResponse {
                success: false,
                message: format!("Transaction failed: {}", e),
                transaction_digest: None,
                explorer_url: None,
                key_id: "failed".to_string(),
                from_address: "unknown".to_string(),
                to_address: target_address,
                amount_mist,
                amount_iota,
                executed_at: Utc::now(),
            };

            Ok(Json(response))
        }
    }
}

/// List all vault keys with their IOTA addresses
pub async fn list_keys(State(state): State<AppState>) -> AppResult<Json<ListKeysResponse>> {
    info!("📋 Listing vault keys");

    let keys = state.transaction_service.list_vault_keys().await?;

    let response = ListKeysResponse {
        total: keys.len(),
        keys,
    };

    Ok(Json(response))
}