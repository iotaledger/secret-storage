// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use aws_sdk_kms::types::KeySpec as AwsKeySpec;
use aws_sdk_kms::types::SigningAlgorithmSpec as AwsSigningAlgorithmSpec;
use typed_key_signature::KeyType;
use serde::Deserialize;
use serde::Serialize;
use std::str::FromStr;

use crate::error::AwsKmsError;
use crate::AwsKmsKeyOptions;

#[derive(Debug, Clone)]
pub enum RegionIdentifier {
  Region(String),
  Profile(String),
}

/// Configuration for AWS KMS adapter
#[derive(Debug, Clone)]
pub struct AwsKmsConfig {
  /// AWS region identifier
  pub region: String,
  /// Default options for key generation/import
  pub key_options: AwsKmsKeyOptions,
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
  /// Create new configuration with custom parameters
  pub fn new(region: String) -> Self {
    Self {
      region,
      key_options: AwsKmsKeyOptions::default(),
    }
  }

  pub fn with_key_options(self, key_options: AwsKmsKeyOptions) -> Self {
    Self { key_options, ..self }
  }
}

#[cfg(feature = "env")]
mod from_env {
  use std::env;

  use super::*;

  impl AwsKmsConfig {
    /// Create configuration from environment variables
    pub fn from_env() -> Result<Self, AwsKmsError> {
      let region = env::var("AWS_REGION")
        .or_else(|_| env::var("AWS_DEFAULT_REGION"))
        .map_err(|_| AwsKmsError::MissingEnvVar("AWS_REGION or AWS_DEFAULT_REGION".to_string()))?;

      Ok(Self {
        region,
        key_options: AwsKmsKeyOptions::default(),
      })
    }
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
#[derive(Debug, Copy, Clone, Serialize, Deserialize, strum::IntoStaticStr, strum::EnumString, strum::Display)]
#[non_exhaustive]
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
}

impl Default for KeySpec {
  /// Default behavior for [secret_storage::KeySign] trait.
  fn default() -> Self {
    KeySpec::EccNistEdwards25519
  }
}

impl TryInto<AwsKeySpec> for KeySpec {
  type Error = AwsKmsError;

  fn try_into(self) -> Result<AwsKeySpec, Self::Error> {
    let serialized: &str = self.into();
    AwsKeySpec::try_parse(serialized).map_err(|err| {
      AwsKmsError::InvalidKeyFormat(format!("`KeySpec` {serialized} not supported by AWS `KeySpec`; {err}"))
    })
  }
}

impl TryInto<KeySpec> for AwsKeySpec {
  type Error = AwsKmsError;

  fn try_into(self) -> Result<KeySpec, Self::Error> {
    let serialized = self.to_string();
    KeySpec::from_str(&serialized).map_err(|err| {
      AwsKmsError::InvalidKeyFormat(format!("AWS `KeySpec` {serialized} not supported by `KeySpec`; {err}"))
    })
  }
}

impl TryFrom<KeySpec> for KeyType {
  type Error = AwsKmsError;

  fn try_from(value: KeySpec) -> Result<Self, Self::Error> {
    let key_type = match value {
      crate::KeySpec::EccNistP256 => Self::Secp256r1DerEncoded,
      crate::KeySpec::EccSecgP256K1 => Self::Secp256k1DerEncoded,
      crate::KeySpec::EccNistEdwards25519 => Self::Ed25519DerEncoded,
    };

    Ok(key_type)
  }
}

impl TryFrom<KeyType> for KeySpec {
  type Error = AwsKmsError;

  fn try_from(value: KeyType) -> Result<Self, Self::Error> {
    let key_spec = match value {
      KeyType::Secp256r1DerEncoded => Self::EccNistP256,
      KeyType::Secp256k1DerEncoded => Self::EccSecgP256K1,
      KeyType::Ed25519DerEncoded => Self::EccNistEdwards25519,
      other => {
        return Err(AwsKmsError::UnsupportedKeyType(other.to_string()));
      }
    };

    Ok(key_spec)
  }
}

/// AWS KMS Key Signing Algorithm Specification
/// Subset of [aws_sdk_kms::types::SigningAlgorithmSpec] supported by `AwsKmsStorage`
#[derive(Debug, Copy, Clone, Serialize, Deserialize, strum::IntoStaticStr, strum::EnumString, strum::Display)]
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

impl TryInto<SigningAlgorithmSpec> for KeyType {
  type Error = AwsKmsError;

  fn try_into(self) -> Result<SigningAlgorithmSpec, Self::Error> {
    let alg = match self {
      KeyType::Ed25519DerEncoded => SigningAlgorithmSpec::Ed25519Sha512,
      KeyType::Secp256k1DerEncoded => SigningAlgorithmSpec::EcdsaSha256,
      KeyType::Secp256r1DerEncoded => SigningAlgorithmSpec::EcdsaSha256,

      _other => {
        return Err(AwsKmsError::UnsupportedKeyUsage(
          "unsupported signature type".to_string(),
        ));
      }
    };

    Ok(alg)
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
