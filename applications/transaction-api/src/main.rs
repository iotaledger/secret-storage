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
    eprintln!("DEBUG: main() entry point reached");

    // Test 1: Basic environment loading
    eprintln!("DEBUG: Testing environment variables...");
    match env::var("VAULT_ADDR") {
        Ok(addr) => eprintln!("DEBUG: VAULT_ADDR = {}", addr),
        Err(_) => eprintln!("DEBUG: VAULT_ADDR not set"),
    }

    // Test 2: Add logging (tracing)
    eprintln!("DEBUG: Initializing logging...");
    tracing_subscriber::fmt()
        .with_env_filter(
            env::var("RUST_LOG").unwrap_or_else(|_| "info,transaction_api=debug".to_string()),
        )
        .with_target(false)
        .compact()
        .init();

    eprintln!("DEBUG: Logging initialized");
    tracing::info!("🚀 Starting IOTA Secret Storage Transaction API");
    eprintln!("DEBUG: After first info log");

    // Test 3: Add configuration loading
    eprintln!("DEBUG: Loading configuration...");
    let config = AppConfig::from_env()?;
    eprintln!("DEBUG: Configuration loaded successfully");
    tracing::info!("📋 Configuration loaded: {}", config.environment);

    // Test 4: CRITICAL - Initialize transaction service (includes Vault and heavy deps)
    eprintln!("DEBUG: Initializing transaction service...");
    let transaction_service = TransactionService::new(&config).await;

    let service = match transaction_service {
        Ok(service) => {
            eprintln!("DEBUG: Transaction service initialized successfully");
            tracing::info!("🔐 Transaction service initialized with {:?} backend", config.storage_backend);
            service
        }
        Err(e) => {
            eprintln!("DEBUG: Transaction service failed: {}", e);
            return Err(format!("Transaction service error: {}", e).into());
        }
    };

    // Create application state
    let app_state = AppState {
        transaction_service: Arc::new(service),
    };

    // Build the HTTP router
    eprintln!("DEBUG: Building HTTP router...");
    let app = api::create_router(app_state);

    // Start the HTTP server
    let bind_addr = format!("{}:{}", config.api_host, config.api_port);
    eprintln!("DEBUG: Starting HTTP server on {}...", bind_addr);
    tracing::info!("🌐 Starting server on {}", bind_addr);

    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .expect("Failed to bind server");

    tracing::info!("✅ Server listening on {}", bind_addr);
    eprintln!("DEBUG: Server listening on {}", bind_addr);

    // Test: spawn a task to print every second to verify tokio runtime works
    tokio::spawn(async {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            eprintln!("DEBUG: Runtime heartbeat - Tokio is alive");
        }
    });

    eprintln!("DEBUG: About to start serving...");

    // Use hyper directly with hyper-util (more reliable than axum::serve)
    use hyper_util::rt::TokioIo;
    use hyper_util::server::conn::auto::Builder;
    use tower::Service;

    eprintln!("DEBUG: Starting hyper server loop...");

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);

        let tower_service = app.clone();

        tokio::spawn(async move {
            eprintln!("DEBUG: New connection accepted!");
            let hyper_service = hyper::service::service_fn(move |request| {
                eprintln!("DEBUG: Request received: {} {}", request.method(), request.uri());
                tower_service.clone().call(request)
            });

            if let Err(err) = Builder::new(hyper_util::rt::TokioExecutor::new())
                .serve_connection(io, hyper_service)
                .await
            {
                eprintln!("Error serving connection: {:?}", err);
            }
        });
    }

    Ok(())
}