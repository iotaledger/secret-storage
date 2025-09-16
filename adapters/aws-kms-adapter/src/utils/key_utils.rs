// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Key identification and management utilities

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
        assert!(!is_alias("arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012")); // ARN
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
        assert!(!is_key_id("arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012")); // ARN
        assert!(!is_key_id("too-short")); // Wrong length
        assert!(!is_key_id("12345678-1234-1234-1234-123456789012-too-long")); // Too long
    }

    #[test]
    fn test_identify_key_type() {
        assert_eq!(identify_key_type("my-alias"), "alias");
        assert_eq!(identify_key_type("user_defined_name"), "alias");
        assert_eq!(identify_key_type("12345678-1234-1234-1234-123456789012"), "KMS key ID");
        assert_eq!(identify_key_type("arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"), "KMS ARN");
        assert_eq!(identify_key_type("unknown-format"), "alias"); // Fallback to alias
    }
}
