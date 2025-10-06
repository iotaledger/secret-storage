// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! IOTA Secret Storage Transaction API
//!
//! Simplified REST API for executing IOTA transactions with Vault backend.
//! Only 2 endpoints: execute transaction and list keys.

use std::{env, sync::Arc};

mod api;
mod config;
mod error;
mod handlers;
mod models;
mod services;

use crate::{
    config::AppConfig,
    services::TransactionService,
};

#[derive(Clone)]
pub struct AppState {
    pub transaction_service: Arc<TransactionService>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            env::var("RUST_LOG").unwrap_or_else(|_| "info,transaction_api=debug".to_string()),
        )
        .with_target(false)
        .compact()
        .init();

    tracing::info!("🚀 Starting IOTA Secret Storage Transaction API");

    // Load configuration
    let config = AppConfig::from_env()?;
    tracing::info!("📋 Configuration loaded: {}", config.environment);

    // Initialize transaction service
    let service = TransactionService::new(&config).await?;
    tracing::info!("🔐 Transaction service initialized with {:?} backend", config.storage_backend);

    // Create application state
    let app_state = AppState {
        transaction_service: Arc::new(service),
    };

    // Build the HTTP router
    let app = api::create_router(app_state);

    // Start the HTTP server
    let bind_addr = format!("{}:{}", config.api_host, config.api_port);
    tracing::info!("🌐 Starting server on {}", bind_addr);

    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .expect("Failed to bind server");

    tracing::info!("✅ Server listening on {}", bind_addr);

    // Use hyper directly with hyper-util
    use hyper_util::rt::TokioIo;
    use hyper_util::server::conn::auto::Builder;
    use tower::Service;

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let tower_service = app.clone();

        tokio::spawn(async move {
            let hyper_service = hyper::service::service_fn(move |request| {
                tower_service.clone().call(request)
            });

            if let Err(err) = Builder::new(hyper_util::rt::TokioExecutor::new())
                .serve_connection(io, hyper_service)
                .await
            {
                tracing::error!("Connection error: {:?}", err);
            }
        });
    }

    Ok(())
}