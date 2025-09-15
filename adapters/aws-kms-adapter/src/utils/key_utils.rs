// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Key identification and management utilities

/// Identify the type of key identifier for logging purposes
pub fn identify_key_type(key_id: &str) -> &'static str {
    if key_id.starts_with("alias/") {
        "alias"
    } else if key_id.starts_with("arn:aws:kms:") {
        "KMS ARN"
    } else if key_id.len() == 36 && key_id.contains('-') {
        "KMS key ID"
    } else {
        "key identifier"
    }
}

/// Check if a string looks like a KMS key alias
pub fn is_alias(key_id: &str) -> bool {
    key_id.starts_with("alias/")
}

/// Check if a string looks like a KMS key ARN
pub fn is_arn(key_id: &str) -> bool {
    key_id.starts_with("arn:aws:kms:")
}

/// Check if a string looks like a KMS key ID (UUID format)
pub fn is_key_id(key_id: &str) -> bool {
    key_id.len() == 36 && key_id.contains('-') && !key_id.starts_with("arn:") && !key_id.starts_with("alias/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identify_key_type() {
        assert_eq!(identify_key_type("alias/my-key"), "alias");
        assert_eq!(identify_key_type("arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"), "KMS ARN");
        assert_eq!(identify_key_type("12345678-1234-1234-1234-123456789012"), "KMS key ID");
        assert_eq!(identify_key_type("some-other-identifier"), "key identifier");
    }

    #[test]
    fn test_key_type_predicates() {
        let alias = "alias/my-key";
        let arn = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012";
        let key_id = "12345678-1234-1234-1234-123456789012";
        let other = "some-other";

        assert!(is_alias(alias));
        assert!(!is_alias(arn));
        assert!(!is_alias(key_id));
        assert!(!is_alias(other));

        assert!(!is_arn(alias));
        assert!(is_arn(arn));
        assert!(!is_arn(key_id));
        assert!(!is_arn(other));

        assert!(!is_key_id(alias));
        assert!(!is_key_id(arn));
        assert!(is_key_id(key_id));
        assert!(!is_key_id(other));
    }
}