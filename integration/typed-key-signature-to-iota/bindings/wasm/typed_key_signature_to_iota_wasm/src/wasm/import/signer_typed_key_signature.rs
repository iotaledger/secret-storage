// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use anyhow::anyhow;
use async_trait::async_trait;
use typed_key_signature::TypedKeySignature;
use secret_storage::Error as SecretStorageError;
use secret_storage::Signer;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsValue;

use crate::error::Result;
use crate::utils::typed_key_signature::TypedKeySignatureInput;
use crate::utils::typed_key_signature::TypedKeySignaturePublicKey;
use crate::utils::typed_key_signature::TypedKeySignatureSignature;

#[wasm_bindgen(typescript_custom_section)]
const I_TX_SIGNER: &str = r#"
import { PublicKey } from "@iota/iota-sdk/cryptography";

export interface SignerTypedKeySignature {
  sign: (tx_data_bcs: Uint8Array) => Promise<TypedKeySignatureSignature>;
  publicKey: () => Promise<TypedKeySignaturePublicKey>;
  keyId: () => string;
}
"#;

#[wasm_bindgen(typescript_custom_section)]
const ISIGNATURE_SCHEME__MULTI_SIGNATURE: &'static str = r#"
export interface TypedKeySignaturePublicKey {
    bytes: Uint8Array;
    keyType: any;
}

export interface TypedKeySignatureSignature {
    bytes: Uint8Array;
    keyType: any;
}
"#;

#[wasm_bindgen]
extern "C" {
    /// Inner signer, that will be used by [IotaCompatibleSigner].
    /// This is the incoming edge for structs/classes that implement `Signer<TypedKeySignature>` in JS/TS.
    #[derive(Clone)]
    #[wasm_bindgen(typescript_type = "SignerTypedKeySignature")]
    pub type WasmSignerTypedKeySignature;

    #[wasm_bindgen(method, structural, catch)]
    // pub async fn sign(this: &WasmSignerTypedKeySignature, tx_data: Vec<u8>) -> Result<JsString>;
    pub async fn sign(this: &WasmSignerTypedKeySignature, tx_data: Vec<u8>) -> Result<JsValue>;

    #[wasm_bindgen(js_name = "publicKey", method, structural, catch)]
    pub async fn public_key(this: &WasmSignerTypedKeySignature) -> Result<JsValue>;

    #[wasm_bindgen(js_name = "keyId", method, structural)]
    pub fn key_id(this: &WasmSignerTypedKeySignature) -> String;
}

// Implements traits required for `IotaCompatibleSigner` to consume `WasmSignerTypedKeySignature` as an inner signer.
#[async_trait(?Send)]
impl Signer<TypedKeySignature> for WasmSignerTypedKeySignature {
    type KeyId = String;

    async fn sign(
        &self,
        data: &TypedKeySignatureInput,
    ) -> std::result::Result<TypedKeySignatureSignature, SecretStorageError> {
        let signature_js: JsValue = self.sign(data.clone()).await.map_err(|err| {
            let details = err
                .as_string()
                .map(|v| format!("; {v}"))
                .unwrap_or_default();
            let message = format!("could not sign data; {details}");
            SecretStorageError::Other(anyhow!(message))
        })?;
        let signature_parsed = serde_wasm_bindgen::from_value(signature_js).map_err(|err| {
            let details = err.to_string();
            let message = format!("could not parse signature; {details}");
            SecretStorageError::Other(anyhow!(message))
        })?;

        Ok(signature_parsed)
    }

    async fn public_key(
        &self,
    ) -> std::result::Result<TypedKeySignaturePublicKey, SecretStorageError> {
        let public_key_js: JsValue = self.public_key().await.map_err(|err| {
            let details = err
                .as_string()
                .map(|v| format!("; {v}"))
                .unwrap_or_default();
            let message = format!("could not get public key; {details}");
            SecretStorageError::Other(anyhow!(message))
        })?;
        let public_key_parsed = serde_wasm_bindgen::from_value(public_key_js).map_err(|err| {
            let details = err.to_string();
            let message = format!("could not parse public key; {details}");
            SecretStorageError::Other(anyhow!(message))
        })?;

        Ok(public_key_parsed)
    }

    fn key_id(&self) -> String {
        self.key_id()
    }
}
