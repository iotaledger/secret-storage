// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Key identification and management utilities

use aws_sdk_kms::types::KeySpec;
use aws_sdk_kms::Client as KmsClient;
use secret_storage::Result;

use crate::AwsKmsError;

/// Identify the type of key identifier for logging purposes
pub fn identify_key_type(key_id: &str) -> &'static str {
    if is_arn(key_id) {
        "KMS ARN"
    } else if is_key_id(key_id) {
        "KMS key ID"
    } else if is_alias(key_id) {
        "alias"
    } else {
        "key identifier"
    }
}

/// Check if a string looks like a KMS key alias
/// An alias is any string that is not a KMS key ID or ARN
pub fn is_alias(key_id: &str) -> bool {
    !is_key_id(key_id) && !is_arn(key_id) && !key_id.is_empty()
}

/// Check if a string looks like a KMS key ARN
pub fn is_arn(key_id: &str) -> bool {
    key_id.starts_with("arn:aws:kms:")
}

/// Check if a string looks like a KMS key ID (UUID format)
pub fn is_key_id(key_id: &str) -> bool {
    key_id.len() == 36
        && key_id.chars().filter(|&c| c == '-').count() == 4  // UUID has 4 hyphens
        && !key_id.starts_with("arn:")
}

pub(crate) async fn get_public_key_der(
    client: &KmsClient,
    key_id: &str,
) -> Result<(Vec<u8>, KeySpec)> {
    // AWS KMS get_public_key accepts both aliases and KMS key IDs
    let public_key_response = client
        .get_public_key()
        .key_id(key_id)
        .send()
        .await
        .map_err(|e| {
            AwsKmsError::General(format!(
                "Failed to get public key from KMS: {}",
                e.into_source().unwrap()
            ))
        })
        .unwrap();

    let public_key_der = public_key_response
        .public_key
        .ok_or_else(|| AwsKmsError::General("No public key returned from KMS".to_string()))?
        .into_inner();

    // Get the actual KMS key ID for logging and validation
    let actual_key_id = public_key_response.key_id.as_deref().unwrap_or("unknown");

    // Verify it's the expected key type
    if let Some(key_usage) = public_key_response.key_usage {
        if key_usage != aws_sdk_kms::types::KeyUsageType::SignVerify {
            return Err(AwsKmsError::General(format!(
                "Key {} (actual ID: {}) is not for signing, got usage: {:?}",
                key_id, actual_key_id, key_usage
            ))
            .into());
        }
    }

    let key_spec = public_key_response.key_spec.ok_or_else(|| {
        AwsKmsError::General(format!("Key {} is missing KeySpec information", key_id))
    })?;

    Ok((public_key_der, key_spec.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alias_detection() {
        // Alias names (any user string)
        assert!(is_alias("my-key"));
        assert!(is_alias("aws-kms-demo-123"));
        assert!(is_alias("test-alias"));
        assert!(is_alias("user_defined_name"));

        // Not aliases
        assert!(!is_alias("12345678-1234-1234-1234-123456789012")); // KMS key ID
        assert!(!is_alias(
            "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
        )); // ARN
        assert!(!is_alias("")); // Empty string
    }

    #[test]
    fn test_key_id_detection() {
        // Valid KMS key IDs
        assert!(is_key_id("12345678-1234-1234-1234-123456789012"));
        assert!(is_key_id("abcdefgh-1234-5678-9abc-def123456789"));

        // Not KMS key IDs
        assert!(!is_key_id("my-alias")); // Alias
        assert!(!is_key_id("alias/my-alias")); // Alias with prefix
        assert!(!is_key_id(
            "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
        )); // ARN
        assert!(!is_key_id("too-short")); // Wrong length
        assert!(!is_key_id("12345678-1234-1234-1234-123456789012-too-long")); // Too long
    }

    #[test]
    fn test_identify_key_type() {
        assert_eq!(identify_key_type("my-alias"), "alias");
        assert_eq!(identify_key_type("user_defined_name"), "alias");
        assert_eq!(
            identify_key_type("12345678-1234-1234-1234-123456789012"),
            "KMS key ID"
        );
        assert_eq!(
            identify_key_type(
                "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
            ),
            "KMS ARN"
        );
        assert_eq!(identify_key_type("unknown-format"), "alias"); // Fallback to alias
    }
}
