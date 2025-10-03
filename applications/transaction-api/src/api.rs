// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use axum::{
    routing::{get, post},
    Router,
    Json,
};
use serde::Serialize;
use tower_http::{cors::CorsLayer, trace::TraceLayer};

use crate::{handlers, AppState};

#[derive(Serialize)]
struct SimpleHealth {
    status: String,
}

/// Simple test handler without any dependencies
async fn simple_health() -> Json<SimpleHealth> {
    eprintln!("SIMPLE HEALTH CALLED!");
    Json(SimpleHealth {
        status: "ok".to_string(),
    })
}

/// Create the simplified application router with only 2 endpoints
pub fn create_router(state: AppState) -> Router {
    Router::new()
        // TEST: Simple endpoint without state
        .route("/ping", get(simple_health))

        // Health check for container orchestration
        .route("/health", get(handlers::health_check))

        // Main endpoints
        .route("/execute-transaction", post(handlers::execute_transaction))
        .route("/keys", get(handlers::list_keys))

        .with_state(state)
        .layer(CorsLayer::permissive())
}