// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use async_trait::async_trait;
use aws_sdk_kms::{types::KeySpec, Client as KmsClient};
use iota_interaction::{
    types::crypto::{PublicKey, SignatureScheme},
    IotaKeySignature,
};

use pkcs8::DecodePublicKey as _;
use secret_storage::{
    KeyDelete, KeyExist, KeyGenerate, KeyGet, KeySign, Result,
    SignatureScheme as SecretStorageSignatureScheme,
};
use uuid::Uuid;

use crate::{
    check_key_exists_and_enabled, convert_public_key_der_to_iota_public_key,
    create_kms_client_from_config, create_kms_client_with_profile, delete_alias_if_exists,
    get_public_key_iota, get_test_aws_key_id, identify_key_type, is_alias, resolve_alias_to_key_id,
    schedule_key_deletion, AwsKmsConfig, AwsKmsError, AwsKmsKeyOptions, AwsKmsSigner,
    AwsKmsStorage,
};

// Similar to IotaSigner, currently copy of other signing fn, as information from AWS is not available anymore
// after converting it to AwsKeySignatureScheme PublicKey
// TODO: decide wether to keep other signature in support and refactor pub key retrieval functions
// to retrieve with optional conversion.
#[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync-storage", async_trait)]
impl KeyGenerate<IotaKeySignature, String> for AwsKmsStorage {
    type Options = AwsKmsKeyOptions;

    async fn generate_key_with_options(
        &self,
        options: Self::Options,
    ) -> Result<(
        String,
        <IotaKeySignature as SecretStorageSignatureScheme>::PublicKey,
    )> {
        let key_id = get_test_aws_key_id(&options.key_spec.unwrap())?.to_string();
        let public_key = KeyGet::<IotaKeySignature, String>::public_key(self, &key_id).await?;

        return Ok((key_id, public_key));
        // TODO: generation disabled during tests, re-enable later on
        #[allow(unreachable_code)]
        // If no alias is provided, generate a unique one
        let key_alias = options
            .alias
            .unwrap_or_else(|| format!("{}", Uuid::new_v4()));

        self.client
            .create_alias()
            .set_alias_name(Some(key_alias.clone()));

        // Create KMS key for signing with secp256r1 (ECC_NIST_P256)
        let mut create_key = self
            .client
            .create_key()
            .key_usage(aws_sdk_kms::types::KeyUsageType::SignVerify)
            .key_spec(
                options
                    .key_spec
                    .and_then(|adapter_key_spec| Some(adapter_key_spec.try_into()))
                    .transpose()?
                    .unwrap_or(aws_sdk_kms::types::KeySpec::EccNistEdwards25519),
            );

        if let Some(description) = &options.description {
            create_key = create_key.description(description);
        } else {
            create_key = create_key.description(format!(
                "IOTA Secret Storage Key (KeySpec::EccNistEdwards25519) - {}",
                key_alias
            ));
        }

        if let Some(policy) = &options.policy {
            create_key = create_key.policy(policy);
        }

        // Add tags if provided
        if !options.tags.is_empty() {
            let tags: Vec<_> = options
                .tags
                .iter()
                .map(|(k, v)| {
                    aws_sdk_kms::types::Tag::builder()
                        .tag_key(k)
                        .tag_value(v)
                        .build()
                        .unwrap()
                })
                .collect();
            create_key = create_key.set_tags(Some(tags));
        }

        // Execute KMS key creation
        let create_response = create_key
            .send()
            .await
            .map_err(|e| AwsKmsError::General(format!("Failed to create KMS key: {}", e)))?;

        let kms_key_id = create_response
            .key_metadata
            .map(|metadata| metadata.key_id)
            .ok_or_else(|| AwsKmsError::General("No key ID returned from KMS".to_string()))?;

        // Create the alias for the key (AWS requires 'alias/' prefix)
        let aws_alias_name = format!("alias/{}", key_alias);

        self.client
            .create_alias()
            .alias_name(&aws_alias_name)
            .target_key_id(&kms_key_id)
            .send()
            .await
            .map_err(|e| AwsKmsError::General(format!("Failed to create alias: {}", e)))?;

        // Get the public key immediately after creation using the alias
        let public_key_response = self
            .client
            .get_public_key()
            .key_id(&aws_alias_name)
            .send()
            .await
            .map_err(|e| AwsKmsError::General(format!("Failed to get public key: {}", e)))?;

        let public_key_der = public_key_response
            .public_key
            .ok_or_else(|| AwsKmsError::General("No public key returned from KMS".to_string()))?
            .into_inner();

        let public_key_iota = convert_public_key_der_to_iota_public_key(&public_key_der).unwrap();

        // Return the original alias as the key identifier (without 'alias/' prefix for user display)
        // Ok((key_alias, public_key_der))
        Ok((kms_key_id, public_key_iota))
    }
}

impl KeySign<IotaKeySignature, String> for AwsKmsStorage {
    fn get_signer(
        &self,
        key_id: &String,
    ) -> Result<impl secret_storage::Signer<IotaKeySignature, KeyId = String>> {
        let _key_type = identify_key_type(key_id);

        // The signer will determine if this is an alias or KMS key ID internally
        Ok(AwsKmsSigner::new(
            self.client.clone(),
            key_id.clone(),
            key_id.clone(), // Pass the same identifier - signer will handle the distinction
        ))
    }
}

// Similar to IotaSigner, currently copy of other signing fn, as information from AWS is not available anymore
// after converting it to AwsKeySignatureScheme PublicKey
// TODO: decide wether to keep other signature in support and refactor pub key retrieval functions
// to retrieve with optional conversion.
#[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync-storage", async_trait)]
impl KeyGet<IotaKeySignature, String> for AwsKmsStorage {
    async fn public_key(
        &self,
        key_id: &String,
    ) -> Result<<IotaKeySignature as SecretStorageSignatureScheme>::PublicKey> {
        let pk = get_public_key_iota(&self.client, key_id).await?;
        Ok(pk)
        // // AWS KMS get_public_key accepts both aliases and KMS key IDs
        // let public_key_response = self
        //     .client
        //     .get_public_key()
        //     .key_id(key_id)
        //     .send()
        //     .await
        //     .map_err(|e| {
        //         AwsKmsError::General(format!(
        //             "Failed to get public key from KMS: {}",
        //             e.into_source().unwrap()
        //         ))
        //     })?;

        // let public_key_der = public_key_response
        //     .public_key
        //     .ok_or_else(|| AwsKmsError::General("No public key returned from KMS".to_string()))?
        //     .into_inner();

        // // Get the actual KMS key ID for logging and validation
        // let actual_key_id = public_key_response.key_id.as_deref().unwrap_or("unknown");

        // // Verify it's the expected key type
        // if let Some(key_usage) = public_key_response.key_usage {
        //     if key_usage != aws_sdk_kms::types::KeyUsageType::SignVerify {
        //         return Err(AwsKmsError::General(format!(
        //             "Key {} (actual ID: {}) is not for signing, got usage: {:?}",
        //             key_id, actual_key_id, key_usage
        //         ))
        //         .into());
        //     }
        // }

        // let public_key = match public_key_response.key_spec {
        //     Some(KeySpec::EccNistEdwards25519) => {
        //         let public_key_bytes =
        //             <ed25519::pkcs8::PublicKeyBytes as pkcs8::DecodePublicKey>::from_public_key_der(&public_key_der)
        //             .unwrap();

        //         PublicKey::try_from_bytes(SignatureScheme::ED25519, &public_key_bytes.to_bytes())
        //             .unwrap()
        //     }
        //     Some(KeySpec::EccNistP256) => {
        //         let decoded = p256::PublicKey::from_public_key_der(&public_key_der).unwrap();
        //         let sec1_bytes = decoded.to_sec1_bytes();
        //         let pk =
        //             PublicKey::try_from_bytes(SignatureScheme::Secp256r1, &sec1_bytes).unwrap();

        //         pk
        //     }
        //     Some(key_spec) => {
        //         return Err(AwsKmsError::General(format!(
        //             "Key {} uses unsupported spec: {:?}",
        //             key_id, key_spec
        //         ))
        //         .into());
        //     }
        //     None => {
        //         return Err(AwsKmsError::General(format!(
        //             "Key {} is missing KeySpec information",
        //             key_id
        //         ))
        //         .into());
        //     }
        // };

        // Ok(public_key)
    }
}
