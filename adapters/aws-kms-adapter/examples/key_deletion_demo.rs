// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Demonstration of key deletion functionality with AWS KMS
//!
//! This example shows how to:
//! 1. Create keys with aliases
//! 2. Delete keys using both aliases and KMS key IDs
//! 3. Handle the AWS KMS deletion process correctly
//!
//! Usage:
//! ```bash
//! AWS_PROFILE=your-profile-name AWS_REGION=eu-west-1 cargo run --example key_deletion_demo
//! ```

use aws_kms_adapter::{AwsKmsKeyOptions, AwsKmsStorage};
use secret_storage::{KeyDelete, KeyExist, KeyGenerate};
use std::env;


fn print_header() {
    println!("\n🗑️ AWS KMS Key Deletion Demo");
    println!("{}", "=".repeat(50));
    println!("This demo shows deletion of keys via alias and KMS key ID");
    println!();
}

async fn create_test_key(
    storage: &AwsKmsStorage,
    alias: &str,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    let session_id = chrono::Utc::now().timestamp_millis();
    let full_alias = format!("{}-{}", alias, session_id);
    println!("🔧 Creating test key with alias: {}", full_alias);

    let options = AwsKmsKeyOptions {
        alias: Some(full_alias.clone()),
        description: Some(format!("Test key for deletion demo: {}", full_alias)),
        policy: None,
        tags: vec![
            ("Purpose".to_string(), "DeletionDemo".to_string()),
            ("Temporary".to_string(), "true".to_string()),
        ],
    };

    let (returned_alias, _public_key) = storage.generate_key_with_options(options).await?;

    // Get the actual KMS key ID by creating a temporary client for demonstration
    // In a real application, you might want to expose this functionality in the adapter
    let aws_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .load()
        .await;
    let temp_client = aws_sdk_kms::Client::new(&aws_config);

    let describe_response = temp_client
        .describe_key()
        .key_id(&returned_alias)
        .send()
        .await?;

    let kms_key_id = describe_response
        .key_metadata
        .map(|m| m.key_id)
        .ok_or("No key metadata found")?;

    println!("✅ Created key:");
    println!("   Alias: {}", returned_alias);
    println!("   KMS Key ID: {}", kms_key_id);

    Ok((returned_alias, kms_key_id))
}

async fn demo_alias_deletion(storage: &AwsKmsStorage) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n📋 Demo 1: Deletion via Alias");
    println!("{}", "-".repeat(30));

    let (alias, kms_key_id) = create_test_key(storage, "iota-demo-secp256r1-key").await?;

    println!("\n🗑️ Deleting key via alias...");
    storage.delete(&alias).await?;

    println!("✅ Deletion via alias completed");
    println!("   • Alias was deleted: {}", alias);
    println!("   • KMS key scheduled for deletion: {}", kms_key_id);

    Ok(())
}

async fn demo_kms_id_deletion(storage: &AwsKmsStorage) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n📋 Demo 2: Deletion via KMS Key ID");
    println!("{}", "-".repeat(30));

    let (_alias, kms_key_id) = create_test_key(storage, "deletion-demo-kms-id").await?;

    println!("\n🗑️ Deleting key via KMS key ID...");
    storage.delete(&kms_key_id).await?;

    println!("✅ Deletion via KMS key ID completed");
    println!("   • KMS key scheduled for deletion: {}", kms_key_id);
    println!("   • Note: Alias still exists but points to deleted key");

    Ok(())
}

async fn demo_verification(storage: &AwsKmsStorage) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n📋 Demo 3: Verification After Deletion");
    println!("{}", "-".repeat(30));

    // Create a key we'll verify deletion for
    let (alias, _kms_key_id) = create_test_key(storage, "deletion-demo-verify").await?;

    // Verify it exists before deletion
    let exists_before = storage.exist(&alias).await?;
    println!("🔍 Key exists before deletion: {}", exists_before);

    // Delete it
    storage.delete(&alias).await?;

    // Wait a moment and check again
    println!("⏳ Checking existence after deletion...");
    let exists_after = storage.exist(&alias).await?;
    println!("🔍 Key exists after deletion: {}", exists_after);

    if !exists_after {
        println!("✅ Key properly marked as non-existent after deletion");
    } else {
        println!("⚠️ Key still shows as existing (this is normal during the waiting period)");
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    print_header();

    // Initialize storage
    let storage = if env::var("AWS_PROFILE").is_ok() {
        println!("🔑 Using AWS profile authentication");
        AwsKmsStorage::with_profile(env::var("AWS_PROFILE").ok().as_deref()).await?
    } else {
        println!("🔑 Using environment variable authentication");
        AwsKmsStorage::from_env().await?
    };

    // Run deletion demos
    demo_alias_deletion(&storage).await?;
    demo_kms_id_deletion(&storage).await?;
    demo_verification(&storage).await?;

    // Final summary
    println!("\n🎉 Key Deletion Demo Completed!");
    println!("{}", "=".repeat(50));
    println!("✅ Demonstrated deletion via alias");
    println!("✅ Demonstrated deletion via KMS key ID");
    println!("✅ Showed verification after deletion");

    println!("\n💡 Key Points:");
    println!("  • AWS KMS requires 7-30 day waiting period for deletion");
    println!("  • Aliases can be deleted independently of keys");
    println!("  • Keys can be cancelled during waiting period");
    println!("  • Both alias and KMS key ID formats are supported");

    println!("\n⚠️ Important:");
    println!("  Check your AWS KMS console to see scheduled deletions");
    println!("  Cancel any test key deletions if you want to keep them");

    Ok(())
}
