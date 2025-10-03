// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Debug version of transaction-api main to isolate startup issues

use std::env;

fn main() {
    println!("DEBUG: Starting debug version...");

    // Test 1: Basic println
    println!("DEBUG: Basic println works");

    // Test 2: Environment variables
    println!("DEBUG: Reading environment variables...");
    if let Ok(vault_addr) = env::var("VAULT_ADDR") {
        println!("DEBUG: VAULT_ADDR = {}", vault_addr);
    } else {
        println!("DEBUG: VAULT_ADDR not set");
    }

    if let Ok(vault_token) = env::var("VAULT_TOKEN") {
        println!("DEBUG: VAULT_TOKEN = {}", vault_token);
    } else {
        println!("DEBUG: VAULT_TOKEN not set");
    }

    // Test 3: Config loading
    println!("DEBUG: Testing config loading...");
    match crate::config::AppConfig::from_env() {
        Ok(config) => {
            println!("DEBUG: Config loaded successfully: {:?}", config.storage_backend);
        }
        Err(e) => {
            println!("DEBUG: Config loading failed: {}", e);
            std::process::exit(1);
        }
    }

    // Test 4: Async runtime
    println!("DEBUG: Testing async runtime...");
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => {
            println!("DEBUG: Tokio runtime created successfully");
            rt
        }
        Err(e) => {
            println!("DEBUG: Failed to create tokio runtime: {}", e);
            std::process::exit(1);
        }
    };

    // Test 5: Vault service initialization
    println!("DEBUG: Testing Vault service initialization...");
    rt.block_on(async {
        println!("DEBUG: Inside async block");

        match crate::config::AppConfig::from_env() {
            Ok(config) => {
                println!("DEBUG: Config loaded in async context");

                match crate::services::TransactionService::new(&config).await {
                    Ok(_service) => {
                        println!("DEBUG: TransactionService created successfully");
                    }
                    Err(e) => {
                        println!("DEBUG: TransactionService creation failed: {}", e);
                        std::process::exit(1);
                    }
                }
            }
            Err(e) => {
                println!("DEBUG: Config loading failed in async: {}", e);
                std::process::exit(1);
            }
        }
    });

    println!("DEBUG: All tests passed - debug version completed successfully");
}

// Include necessary modules
mod config;
mod error;
mod services;