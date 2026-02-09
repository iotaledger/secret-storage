// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use aws_sdk_kms::types::KeySpec as AwsKeySpec;
use aws_sdk_kms::types::SigningAlgorithmSpec as AwsSigningAlgorithmSpec;
use serde::Deserialize;
use serde::Serialize;
use std::env;
use std::str::FromStr;

use crate::error::AwsKmsError;

#[derive(Debug, Clone)]
pub enum RegionIdentifier {
    Region(String),
    Profile(String),
}

/// Configuration for AWS KMS adapter
#[derive(Debug, Clone)]
pub struct AwsKmsConfig {
    /// AWS region identifier (region name or profile in local config)
    pub region: Option<RegionIdentifier>,
    /// signing algorithm used for transaction signing
    pub transaction_signing_algorithm: Option<SigningAlgorithmSpec>,
}

/// AWS KMS Key Usage types
#[derive(Debug, Clone)]
pub enum KeyUsage {
    /// For digital signatures
    SignVerify,
    /// For encryption/decryption
    EncryptDecrypt,
}

impl AwsKmsConfig {
    /// Create configuration from environment variables
    pub fn new_from_env() -> Result<Self, AwsKmsError> {
        let region = env::var("AWS_REGION")
            .or_else(|_| env::var("AWS_DEFAULT_REGION"))
            .map_err(|_| {
                AwsKmsError::MissingEnvVar("AWS_REGION or AWS_DEFAULT_REGION".to_string())
            })?;

        let transaction_signing_algorithm: SigningAlgorithmSpec = serde_json::from_str(
            &env::var("SIGNING_ALGORITHM_SPEC")
                .map_err(|_| AwsKmsError::MissingEnvVar("SIGNING_ALGORITHM_SPEC".to_string()))?,
        )
        .unwrap();

        Ok(Self {
            region: Some(RegionIdentifier::Region(region)),
            transaction_signing_algorithm: Some(transaction_signing_algorithm),
        })
    }

    /// Create new configuration with custom parameters
    pub fn new() -> Self {
        Self {
            region: None,
            transaction_signing_algorithm: None,
        }
    }

    /// Set region
    pub fn with_region(mut self, region: String) -> Self {
        self.region = Some(RegionIdentifier::Region(region));
        self
    }

    /// Set Profile
    pub fn with_profile(mut self, profile: String) -> Self {
        self.region = Some(RegionIdentifier::Profile(profile));
        self
    }

    /// Set signing algorithm used for transaction signing
    pub fn with_transaction_signing_algorithm(
        mut self,
        transaction_signing_algorithm: SigningAlgorithmSpec,
    ) -> Self {
        self.transaction_signing_algorithm = Some(transaction_signing_algorithm);
        self
    }
}

/// Create new enum as subset of external enum
#[macro_export]
macro_rules! sub_enum {
    ($sub_enum_name:ident of $super_enum_name:ty {
        $($variant:ident),* $(,)?
    }) => {
        #[derive(Debug, Clone, Serialize, Deserialize, strum::IntoStaticStr, strum::EnumString)]
        pub enum $sub_enum_name {
            $($variant,)*
        }

        impl From<$sub_enum_name> for $super_enum_name {
            fn from(val: $sub_enum_name) -> $super_enum_name {
                match val {
                    $(<$sub_enum_name>::$variant => <$super_enum_name>::$variant,)*
                }
            }
        }

        impl std::convert::TryFrom<$super_enum_name> for $sub_enum_name {
            type Error = AwsKmsError;
            fn try_from(val: $super_enum_name) -> Result<Self, Self::Error> {
                match val {
                    $(<$super_enum_name>::$variant => Ok(Self::$variant),)*
                    _ => Err(AwsKmsError::InvalidKeyFormat(
                        "SigningAlgorithmSpec variant $variant not supported".to_string()
                    ))
                }
            }
        }
    }
}

/// AWS KMS Key Specification
/// Subset of [aws_sdk_kms::types::KeySpec] supported by `AwsKmsStorage`
#[derive(
    Debug,
    Copy,
    Clone,
    Serialize,
    Deserialize,
    strum::IntoStaticStr,
    strum::EnumString,
    strum::Display,
)]
pub enum KeySpec {
    /// ECC_NIST_EDWARDS25519 for EdDSA signatures
    #[strum(to_string = "ECC_NIST_EDWARDS25519")]
    EccNistEdwards25519,
    /// ECC_NIST_P256 for ECDSA signatures
    #[strum(to_string = "ECC_NIST_P256")]
    EccNistP256,
    /// ECC_SECG_P256K1 for secp256k1 signatures
    #[strum(to_string = "ECC_SECG_P256K1")]
    EccSecgP256K1,
    // disabled for now, as storage impl focuses on the three above for the moment
    // /// RSA_2048 for RSA signatures
    // #[strum(to_string = "RSA_2048")]
    // Rsa2048,
    // /// RSA_4096 for RSA signatures
    // #[strum(to_string = "RSA_4096")]
    // Rsa4096,
    // /// SYMMETRIC_DEFAULT for symmetric encryption
    // #[strum(to_string = "SYMMETRIC_DEFAULT")]
    // SymmetricDefault,
}

impl TryInto<AwsKeySpec> for KeySpec {
    type Error = AwsKmsError;

    fn try_into(self) -> Result<AwsKeySpec, Self::Error> {
        let serialized: &str = self.into();
        AwsKeySpec::try_parse(serialized).map_err(|err| {
            AwsKmsError::InvalidKeyFormat(format!(
                "`KeySpec` {serialized} not supported by AWS `KeySpec`; {err}"
            ))
        })
    }
}

impl TryInto<KeySpec> for AwsKeySpec {
    type Error = AwsKmsError;

    fn try_into(self) -> Result<KeySpec, Self::Error> {
        let serialized = self.to_string();
        KeySpec::from_str(&serialized).map_err(|err| {
            AwsKmsError::InvalidKeyFormat(format!(
                "AWS `KeySpec` {serialized} not supported by `KeySpec`; {err}"
            ))
        })
    }
}

/// AWS KMS Key Signing Algorithm Specification
/// Subset of [aws_sdk_kms::types::SigningAlgorithmSpec] supported by `AwsKmsStorage`
#[derive(
    Debug, Clone, Serialize, Deserialize, strum::IntoStaticStr, strum::EnumString, strum::Display,
)]
pub enum SigningAlgorithmSpec {
    #[strum(to_string = "ECDSA_SHA_256")]
    EcdsaSha256,
    #[strum(to_string = "ECDSA_SHA_384")]
    EcdsaSha384,
    #[strum(to_string = "ECDSA_SHA_512")]
    EcdsaSha512,
    #[strum(to_string = "ED25519_PH_SHA_512")]
    Ed25519PhSha512,
    #[strum(to_string = "ED25519_SHA_512")]
    Ed25519Sha512,
    #[strum(to_string = "ML_DSA_SHAKE_256")]
    MlDsaShake256,
    #[strum(to_string = "RSASSA_PKCS1_V1_5_SHA_256")]
    RsassaPkcs1V15Sha256,
    #[strum(to_string = "RSASSA_PKCS1_V1_5_SHA_384")]
    RsassaPkcs1V15Sha384,
    #[strum(to_string = "RSASSA_PKCS1_V1_5_SHA_512")]
    RsassaPkcs1V15Sha512,
    #[strum(to_string = "RSASSA_PSS_SHA_256")]
    RsassaPssSha256,
    #[strum(to_string = "RSASSA_PSS_SHA_384")]
    RsassaPssSha384,
    #[strum(to_string = "RSASSA_PSS_SHA_512")]
    RsassaPssSha512,
    #[strum(to_string = "SM2DSA")]
    Sm2Dsa,
}

impl TryInto<AwsSigningAlgorithmSpec> for SigningAlgorithmSpec {
    type Error = AwsKmsError;

    fn try_into(self) -> Result<AwsSigningAlgorithmSpec, Self::Error> {
        let serialized: &str = self.into();
        AwsSigningAlgorithmSpec::try_parse(serialized).map_err(|err| {
            AwsKmsError::InvalidKeyFormat(format!(
                "`SigningAlgorithmSpec` {serialized} not supported by AWS `SigningAlgorithmSpec`; {err}"
            ))
        })
    }
}

impl TryInto<SigningAlgorithmSpec> for AwsSigningAlgorithmSpec {
    type Error = AwsKmsError;

    fn try_into(self) -> Result<SigningAlgorithmSpec, Self::Error> {
        let serialized = self.to_string();
        SigningAlgorithmSpec::from_str(&serialized).map_err(|err| {
            AwsKmsError::InvalidKeyFormat(format!(
                "AWS `SigningAlgorithmSpec` {serialized} not supported by `SigningAlgorithmSpec`; {err}"
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
