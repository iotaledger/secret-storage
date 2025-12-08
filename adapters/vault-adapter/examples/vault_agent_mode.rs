// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Vault Agent sidecar mode example
//!
//! This example demonstrates how to use the Vault adapter with Vault Agent
//! sidecar pattern in Kubernetes deployments.
//!
//! In this mode:
//! - The app connects to a local Vault Agent proxy (e.g., http://127.0.0.1:8100)
//! - The agent automatically injects X-Vault-Token header in all requests
//! - No VAULT_TOKEN environment variable is required
//! - Token rotation and renewal is handled automatically by the agent
//!
//! Prerequisites:
//! - Vault Agent running locally on port 8100 (or adjust VAULT_ADDR)
//! - Agent configured with auto_auth and api_proxy
//!
//! Usage:
//! ```bash
//! # For testing locally, you can use a Vault Agent with token from file
//! # See: https://developer.hashicorp.com/vault/docs/agent-and-proxy/agent
//!
//! # Set environment variables (no VAULT_TOKEN needed!)
//! export VAULT_ADDR="http://127.0.0.1:8100"
//! export VAULT_AGENT_MODE="true"
//! export VAULT_MOUNT_PATH="transit"
//!
//! # Run the example
//! cargo run --package vault-adapter --example vault_agent_mode
//! ```

use secret_storage::{KeyDelete, KeyGenerate, KeySign, Signer};
use std::env;
use vault_adapter::{VaultConfig, VaultKeyOptions, VaultStorage};

fn print_session_header() {
    let session_id = chrono::Utc::now().timestamp_millis();
    println!("\n🔐 IOTA Secret Storage - Vault Agent Sidecar Mode");
    println!("📅 Session: VAULT_AGENT_{}", session_id);
    println!(
        "🔧 Vault Agent Address: {}",
        env::var("VAULT_ADDR").unwrap_or_else(|_| "http://127.0.0.1:8100".to_string())
    );
    println!("🎯 Agent Mode: Enabled");
    println!("{}", "=".repeat(60));
}

fn print_step(step: u8, title: &str) {
    println!("\n📋 Step {}: {}", step, title);
    println!("{}", "-".repeat(40));
}

async fn demonstrate_agent_mode() -> Result<(), Box<dyn std::error::Error>> {
    print_step(1, "Initialize Vault Storage with Agent Mode");

    // Check that VAULT_AGENT_MODE is set
    let agent_mode = env::var("VAULT_AGENT_MODE")
        .unwrap_or_else(|_| "false".to_string())
        .to_lowercase()
        == "true";

    if !agent_mode {
        println!("⚠️  VAULT_AGENT_MODE is not set to 'true'");
        println!("   This example demonstrates Vault Agent sidecar pattern.");
        println!("   Set VAULT_AGENT_MODE=true to continue.");
        return Err("VAULT_AGENT_MODE not enabled".into());
    }

    println!("✅ Agent mode is enabled");
    println!("   No VAULT_TOKEN required - agent will inject it automatically");

    // Initialize storage from environment
    let storage = VaultStorage::from_env().await?;
    println!("✅ Vault storage initialized successfully");

    print_step(2, "Create Signing Key via Agent");

    let session_id = chrono::Utc::now().timestamp_millis();
    let key_name = format!("agent-demo-{}", session_id);

    println!("📝 Creating ECDSA P-256 signing key...");
    let options = VaultKeyOptions {
        description: Some("IOTA Agent Demo - ECDSA P-256 key".to_string()),
        key_name: Some(key_name.clone()),
    };

    let (key_id, public_key) = storage.generate_key_with_options(options).await?;

    println!("🔑 Key created successfully!");
    println!("   📌 Key ID: {}", key_id);
    println!("   📐 Public Key Size: {} bytes", public_key.len());

    print_step(3, "Sign Data via Agent");

    let message = "Hello from Vault Agent sidecar!".as_bytes().to_vec();
    println!("📝 Message to sign: \"{}\"", String::from_utf8_lossy(&message));

    let signer = storage.get_signer(&key_id)?;
    let signature = signer.sign(&message).await?;

    println!("✅ Signature generated!");
    println!("   📏 Signature Size: {} bytes", signature.len());
    println!(
        "   🔍 Signature (hex): {}...",
        hex::encode(&signature[..std::cmp::min(16, signature.len())])
    );

    print_step(4, "Cleanup");

    println!("🗑️ Deleting test key...");
    storage.delete(&key_id).await?;
    println!("✅ Key deleted successfully");

    Ok(())
}

async fn demonstrate_programmatic_config() -> Result<(), Box<dyn std::error::Error>> {
    print_step(5, "Programmatic Configuration Example");

    println!("📝 Creating Vault config programmatically for agent mode:");

    let vault_addr = env::var("VAULT_ADDR")
        .unwrap_or_else(|_| "http://127.0.0.1:8100".to_string());

    // Method 1: Using new_agent_mode constructor
    let config = VaultConfig::new_agent_mode(vault_addr.clone());
    println!("   ✅ Method 1: VaultConfig::new_agent_mode()");
    println!("      - Address: {}", config.addr);
    println!("      - Agent Mode: {}", config.agent_mode);
    println!("      - Token: {:?}", config.token);

    // Method 2: Using builder pattern
    let config2 = VaultConfig::new(vault_addr.clone(), "dummy-token".to_string())
        .with_agent_mode(true);
    println!("\n   ✅ Method 2: Builder with with_agent_mode(true)");
    println!("      - Address: {}", config2.addr);
    println!("      - Agent Mode: {}", config2.agent_mode);
    println!("      - Token: {:?}", config2.token);

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    print_session_header();

    // Demonstrate agent mode with real operations
    demonstrate_agent_mode().await?;

    // Show programmatic configuration options
    demonstrate_programmatic_config().await?;

    // Final summary
    println!("\n🎉 Vault Agent Mode Demo Completed!");
    println!("{}", "=".repeat(60));
    println!("✅ Successfully connected via Vault Agent proxy");
    println!("✅ Created and signed with ECDSA P-256 key");
    println!("✅ No VAULT_TOKEN in environment variables");
    println!("✅ Token injected automatically by agent");

    println!("\n💡 Vault Agent Sidecar Benefits:");
    println!("  • No long-lived secrets in application pods");
    println!("  • Automatic token rotation and renewal");
    println!("  • Kubernetes ServiceAccount authentication");
    println!("  • Reduced attack surface");
    println!("  • Zero secret management in application code");

    println!("\n🔧 Kubernetes Deployment:");
    println!("  1. Deploy Vault Agent as sidecar container");
    println!("  2. Configure auto_auth with kubernetes method");
    println!("  3. Enable api_proxy with use_auto_auth_token");
    println!("  4. Set VAULT_ADDR=http://127.0.0.1:8100");
    println!("  5. Set VAULT_AGENT_MODE=true");

    println!("\n📚 Documentation:");
    println!("  - Vault Agent: https://developer.hashicorp.com/vault/docs/agent-and-proxy/agent");
    println!("  - K8s Auth: https://developer.hashicorp.com/vault/docs/auth/kubernetes");
    println!("  - See README.md for complete deployment examples");

    Ok(())
}
