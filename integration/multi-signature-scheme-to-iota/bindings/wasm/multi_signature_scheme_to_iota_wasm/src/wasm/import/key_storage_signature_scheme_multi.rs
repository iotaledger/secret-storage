// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use anyhow::anyhow;
use async_trait::async_trait;
use multi_signature_scheme::KeyType;
use multi_signature_scheme::SignatureSchemeMulti;
use secret_storage::Error as SecretStorageError;
use secret_storage::KeyDelete;
use secret_storage::KeyExist;
use secret_storage::KeyGenerate;
use secret_storage::KeyGet;
use secret_storage::KeySignWithOptions;
use secret_storage::SignatureScheme as SecretStorageSignatureScheme;
use serde::Deserialize;
use wasm_bindgen::prelude::*;

use crate::utils::signature_scheme_multi::SignatureSchemeMultiPublicKey;
use crate::wasm::import::signer_signature_scheme_multi::WasmSignerSignatureSchemeMulti;

#[wasm_bindgen(typescript_custom_section)]
const I_KEY_STORAGE: &str = r#"
export interface KeyStorageSignatureSchemeMulti {
  generateKeyWithOptions(options: any): Promise<{ key_id: string; public_key: SignatureSchemeMultiPublicKey }>;
  publicKey(keyId: string): Promise<SignatureSchemeMultiPublicKey>;
  delete(keyId: string): Promise<void>;
  exist(keyId: string): Promise<boolean>;
  getSignerWithOptions(keyId: string, options: any): SignerSignatureSchemeMulti;
}
"#;

#[wasm_bindgen]
extern "C" {
    /// Incoming JS/TS type representing any object that implements key storage over
    /// `SignatureSchemeMulti`. `AwsKmsStorage` from `aws-kms-adapter-wasm` satisfies this
    /// interface structurally.
    #[derive(Clone)]
    #[wasm_bindgen(typescript_type = "KeyStorageSignatureSchemeMulti")]
    pub type WasmKeyStorageSignatureSchemeMulti;

    #[wasm_bindgen(method, structural, catch, js_name = "generateKeyWithOptions")]
    pub async fn generate_key_with_options(
        this: &WasmKeyStorageSignatureSchemeMulti,
        options: JsValue,
    ) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(method, structural, catch, js_name = "publicKey")]
    pub async fn public_key(
        this: &WasmKeyStorageSignatureSchemeMulti,
        key_id: String,
    ) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(method, structural, catch)]
    pub async fn delete(
        this: &WasmKeyStorageSignatureSchemeMulti,
        key_id: String,
    ) -> Result<(), JsValue>;

    #[wasm_bindgen(method, structural, catch)]
    pub async fn exist(
        this: &WasmKeyStorageSignatureSchemeMulti,
        key_id: String,
    ) -> Result<JsValue, JsValue>;

    /// Synchronous — mirrors `KeySignWithOptions::get_signer_with_options`.
    #[wasm_bindgen(method, structural, js_name = "getSignerWithOptions")]
    pub fn get_signer_with_options(
        this: &WasmKeyStorageSignatureSchemeMulti,
        key_id: String,
        options: JsValue,
    ) -> WasmSignerSignatureSchemeMulti;
}

/// Helper to extract `key_id` and `public_key` from the `NewKeyData` object returned by
/// `AwsKmsStorage.generateKeyWithOptions`. The getter names on that wasm-bindgen class use
/// snake_case, which matches these field names.
#[derive(Deserialize)]
struct NewKeyData {
    key_id: String,
    public_key: SignatureSchemeMultiPublicKey,
}

#[async_trait(?Send)]
impl KeyGenerate<SignatureSchemeMulti, String> for WasmKeyStorageSignatureSchemeMulti {
    type Options = KeyType;

    async fn generate_key_with_options(
        &self,
        options: KeyType,
    ) -> secret_storage::Result<(
        String,
        <SignatureSchemeMulti as SecretStorageSignatureScheme>::PublicKey,
    )> {
        let options_js = serde_wasm_bindgen::to_value(&options)
            .map_err(|e| SecretStorageError::Other(anyhow!("serialize KeyType: {e}")))?;

        let js_value = self
            .generate_key_with_options(options_js)
            .await
            .map_err(|e| SecretStorageError::Other(anyhow!(js_value_to_error_message(e))))?;

        let data: NewKeyData = serde_wasm_bindgen::from_value(js_value)
            .map_err(|e| SecretStorageError::Other(anyhow!("deserialize NewKeyData: {e}")))?;

        Ok((data.key_id, data.public_key))
    }
}

#[async_trait(?Send)]
impl KeyGet<SignatureSchemeMulti, String> for WasmKeyStorageSignatureSchemeMulti {
    async fn public_key(
        &self,
        key_id: &String,
    ) -> secret_storage::Result<<SignatureSchemeMulti as SecretStorageSignatureScheme>::PublicKey>
    {
        let js_value = self
            .public_key(key_id.clone())
            .await
            .map_err(|e| SecretStorageError::Other(anyhow!(js_value_to_error_message(e))))?;

        serde_wasm_bindgen::from_value(js_value)
            .map_err(|e| SecretStorageError::Other(anyhow!("deserialize PublicKey: {e}")))
    }
}

#[async_trait(?Send)]
impl KeyDelete<String> for WasmKeyStorageSignatureSchemeMulti {
    async fn delete(&self, key_id: &String) -> secret_storage::Result<()> {
        self.delete(key_id.clone())
            .await
            .map_err(|e| SecretStorageError::Other(anyhow!(js_value_to_error_message(e))))
    }
}

#[async_trait(?Send)]
impl KeyExist<String> for WasmKeyStorageSignatureSchemeMulti {
    async fn exist(&self, key_id: &String) -> secret_storage::Result<bool> {
        let js_value = self
            .exist(key_id.clone())
            .await
            .map_err(|e| SecretStorageError::Other(anyhow!(js_value_to_error_message(e))))?;

        serde_wasm_bindgen::from_value(js_value)
            .map_err(|e| SecretStorageError::Other(anyhow!("deserialize bool: {e}")))
    }
}

impl KeySignWithOptions<SignatureSchemeMulti, String> for WasmKeyStorageSignatureSchemeMulti {
    type Signer = WasmSignerSignatureSchemeMulti;
    type Options = KeyType;

    fn get_signer_with_options(
        &self,
        key_id: &String,
        options: &KeyType,
    ) -> secret_storage::Result<Self::Signer> {
        let options_js = serde_wasm_bindgen::to_value(options)
            .map_err(|e| SecretStorageError::Other(anyhow!("serialize KeyType: {e}")))?;

        Ok(self.get_signer_with_options(key_id.clone(), options_js))
    }
}

fn js_value_to_error_message(e: JsValue) -> String {
    e.dyn_into::<js_sys::Error>()
        .map(|err| err.message().as_string().unwrap_or_default())
        .unwrap_or_else(|val| format!("{val:?}"))
}
