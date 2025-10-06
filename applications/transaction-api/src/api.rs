// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use axum::{
    routing::{get, post},
    Router,
};
use tower_http::cors::CorsLayer;

use crate::{handlers, AppState};

/// Create the application router
pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(handlers::health_check))
        .route("/execute-transaction", get(handlers::execute_transaction))
        .route("/keys", get(handlers::list_keys))
        .with_state(state)
        .layer(CorsLayer::permissive())
}