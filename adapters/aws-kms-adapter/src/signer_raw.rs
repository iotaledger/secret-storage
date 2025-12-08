// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use async_trait::async_trait;
use secret_storage::{Result, SignatureScheme, SignatureSchemeRaw, Signer};

use crate::AwsKmsSigner;

type SignatureSchemeRawInput = <SignatureSchemeRaw as SignatureScheme>::Input;
type SignatureSchemeRawPublicKey = <SignatureSchemeRaw as SignatureScheme>::PublicKey;
type SignatureSchemeRawSignature = <SignatureSchemeRaw as SignatureScheme>::Signature;

#[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync-storage", async_trait)]
impl Signer<SignatureSchemeRaw> for AwsKmsSigner {
    type KeyId = String;

    async fn sign(&self, _data: &SignatureSchemeRawInput) -> Result<SignatureSchemeRawSignature> {
        todo!();
    }

    async fn public_key(&self) -> Result<SignatureSchemeRawPublicKey> {
        todo!();
    }

    fn key_id(&self) -> Self::KeyId {
        todo!();
    }
}
