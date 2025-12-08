// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use aws_sdk_kms::Client as KmsClient;

use crate::{
    utils::aws_client::{create_kms_client_from_config, create_kms_client_with_profile},
    AwsKmsConfig,
};

// TODO: move impls into separate scopes to make implemented scopes addressable (raw / aws signature schemes)
use async_trait::async_trait;
use secret_storage::{KeyDelete, KeyExist, KeyGenerate, KeyGet, KeySign, Result};
use uuid::Uuid;

use crate::{
    check_key_exists_and_enabled, delete_alias_if_exists, identify_key_type, is_alias,
    resolve_alias_to_key_id, schedule_key_deletion, AwsKmsError, AwsKmsKeyOptions,
    AwsKmsSignatureScheme, AwsKmsSigner, AwsKmsStorage,
};

use secret_storage::{KeySignTest, SignatureSchemeRaw};

impl KeySignTest<SignatureSchemeRaw, String> for AwsKmsStorage {
    type Signer = AwsKmsSigner;
    fn get_signer_test(&self, key_id: &String) -> Result<Self::Signer> {
        let _key_type = identify_key_type(key_id);

        // The signer will determine if this is an alias or KMS key ID internally
        Ok(AwsKmsSigner::new(
            self.client.clone(),
            key_id.clone(),
            key_id.clone(), // Pass the same identifier - signer will handle the distinction
        ))
    }
}
