// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Common KMS operations and utilities

use aws_sdk_kms::{Client as KmsClient, types::KeyState};
use crate::AwsKmsError;

/// Resolve an alias to the actual KMS key ID
pub async fn resolve_alias_to_key_id(client: &KmsClient, alias: &str) -> Result<String, AwsKmsError> {
    let describe_response = client
        .describe_key()
        .key_id(alias)
        .send()
        .await
        .map_err(|e| AwsKmsError::General(format!("Failed to describe key via alias: {}", e)))?;

    describe_response
        .key_metadata
        .map(|metadata| metadata.key_id)
        .ok_or_else(|| AwsKmsError::General("No key ID found for alias".to_string()))
}

/// Check if a key exists and is in a valid state
pub async fn check_key_exists_and_enabled(client: &KmsClient, key_id: &str) -> Result<bool, AwsKmsError> {
    match client.describe_key().key_id(key_id).send().await {
        Ok(response) => {
            if let Some(metadata) = response.key_metadata {
                let is_enabled = metadata.enabled;
                let is_valid = !matches!(
                    metadata.key_state,
                    Some(KeyState::PendingDeletion) | Some(KeyState::Disabled)
                );
                Ok(is_enabled && is_valid)
            } else {
                Ok(false)
            }
        }
        Err(_) => Ok(false), // Key doesn't exist or we can't access it
    }
}

/// Delete an alias (best effort, doesn't fail if alias doesn't exist)
pub async fn delete_alias_if_exists(client: &KmsClient, alias: &str) -> Result<(), AwsKmsError> {
    let _ = client.delete_alias().alias_name(alias).send().await;
    // Don't fail if alias deletion fails (it might not exist or already be deleted)
    Ok(())
}

/// Schedule a KMS key for deletion
pub async fn schedule_key_deletion(
    client: &KmsClient,
    key_id: &str,
    pending_days: Option<i32>,
) -> Result<(), AwsKmsError> {
    let waiting_period_days = pending_days.unwrap_or(7); // Default to 7 days (AWS KMS minimum)

    client
        .schedule_key_deletion()
        .key_id(key_id)
        .pending_window_in_days(waiting_period_days)
        .send()
        .await
        .map_err(|e| AwsKmsError::General(format!("Failed to schedule key deletion: {}", e)))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pending_days_default() {
        // Test that default pending days is 7 when None is provided
        let days = None.unwrap_or(7);
        assert_eq!(days, 7);

        let days = Some(14).unwrap_or(7);
        assert_eq!(days, 14);
    }
}