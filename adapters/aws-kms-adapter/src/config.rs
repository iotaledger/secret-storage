// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use aws_sdk_kms::types::KeySpec as AwsKeySpec;
use serde::{Deserialize, Serialize};
use std::env;

use crate::error::AwsKmsError;

/// Configuration for AWS KMS adapter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwsKmsConfig {
    /// AWS region
    pub region: String,
    /// KMS key ID (optional, can be set per operation)
    pub key_id: Option<String>,
    /// Key usage specification
    pub key_usage: KeyUsage,
    /// Key specification for new keys
    pub key_spec: KeySpec,
}

/// AWS KMS Key Usage types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyUsage {
    /// For digital signatures
    SignVerify,
    /// For encryption/decryption
    EncryptDecrypt,
}

impl AwsKmsConfig {
    /// Create configuration from environment variables
    pub fn from_env() -> Result<Self, AwsKmsError> {
        let region = env::var("AWS_REGION")
            .or_else(|_| env::var("AWS_DEFAULT_REGION"))
            .map_err(|_| {
                AwsKmsError::MissingEnvVar("AWS_REGION or AWS_DEFAULT_REGION".to_string())
            })?;

        let key_id = env::var("KMS_KEY_ID").ok();

        // Default to sign/verify usage with P256 curve
        let key_usage = KeyUsage::SignVerify;
        let key_spec = KeySpec::EccNistP256;

        Ok(Self {
            region,
            key_id,
            key_usage,
            key_spec,
        })
    }

    /// Create new configuration with custom parameters
    pub fn new(region: String) -> Self {
        Self {
            region,
            key_id: None,
            key_usage: KeyUsage::SignVerify,
            key_spec: KeySpec::EccNistP256,
        }
    }

    /// Set KMS key ID
    pub fn with_key_id(mut self, key_id: String) -> Self {
        self.key_id = Some(key_id);
        self
    }

    /// Set key usage
    pub fn with_key_usage(mut self, key_usage: KeyUsage) -> Self {
        self.key_usage = key_usage;
        self
    }

    /// Set key specification
    pub fn with_key_spec(mut self, key_spec: KeySpec) -> Self {
        self.key_spec = key_spec;
        self
    }

    /// Set region
    pub fn with_region(mut self, region: String) -> Self {
        self.region = region;
        self
    }
}

/// AWS KMS Key Specification
#[derive(Debug, Clone, Serialize, Deserialize, strum::IntoStaticStr, strum::EnumString)]
pub enum KeySpec {
    /// ECC_NIST_EDWARDS25519 for EdDSA signatures
    #[strum(to_string = "ECC_NIST_EDWARDS25519")]
    EccNistEdwards25519,
    /// ECC_NIST_P256 for ECDSA signatures
    #[strum(to_string = "CC_NIST_P256")]
    EccNistP256,
    /// ECC_SECG_P256K1 for secp256k1 signatures
    #[strum(to_string = "ECC_SECG_P256K1")]
    EccSecgP256k1,
    /// RSA_2048 for RSA signatures
    #[strum(to_string = "RSA_2048")]
    Rsa2048,
    /// RSA_4096 for RSA signatures  
    #[strum(to_string = "RSA_4096")]
    Rsa4096,
    /// SYMMETRIC_DEFAULT for symmetric encryption
    #[strum(to_string = "SYMMETRIC_DEFAULT")]
    SymmetricDefault,
}

impl KeySpec {
    /// Convert to AWS KMS KeySpec string
    pub fn to_aws_key_spec(&self) -> &'static str {
        // match self {
        //     KeySpec::EccNistEdwards25519 => "ECC_NIST_EDWARDS25519",
        //     KeySpec::EccNistP256 => "ECC_NIST_P256",
        //     KeySpec::EccSecgP256k1 => "ECC_SECG_P256K1",
        //     KeySpec::Rsa2048 => "RSA_2048",
        //     KeySpec::Rsa4096 => "RSA_4096",
        //     KeySpec::SymmetricDefault => "SYMMETRIC_DEFAULT",
        // }
        self.into()
    }
}

impl TryInto<AwsKeySpec> for KeySpec {
    type Error = AwsKmsError;

    fn try_into(self) -> Result<AwsKeySpec, Self::Error> {
        AwsKeySpec::try_parse(self.into()).map_err(|err| {
            AwsKmsError::InvalidKeyFormat(format!(
                "could not convert `KeySpec` to AWS `KeySpec`; {err}"
            ))
        })
    }
}

impl KeyUsage {
    /// Convert to AWS KMS KeyUsage string
    pub fn to_aws_key_usage(&self) -> &'static str {
        match self {
            KeyUsage::SignVerify => "SIGN_VERIFY",
            KeyUsage::EncryptDecrypt => "ENCRYPT_DECRYPT",
        }
    }
}
