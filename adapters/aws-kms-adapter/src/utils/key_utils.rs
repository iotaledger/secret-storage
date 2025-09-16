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
        && !key_id.starts_with("alias/")
}
