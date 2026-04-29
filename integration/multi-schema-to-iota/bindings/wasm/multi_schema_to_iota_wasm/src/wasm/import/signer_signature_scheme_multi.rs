// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use anyhow::anyhow;
use async_trait::async_trait;
use iota_interaction::types::crypto::{PublicKey, Signature, SignatureScheme};
use iota_interaction::types::transaction::TransactionData;
use iota_interaction::IotaKeySignature;
use js_sys::{JsString, Uint8Array};
use multi_schema::SignatureSchemeMulti;
use secret_storage::Error as SecretStorageError;
use secret_storage::Signer;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsValue;

use crate::error::Result;
use crate::utils::signature_scheme_multi::SignatureSchemeMultiInput;
use crate::utils::signature_scheme_multi::SignatureSchemeMultiPublicKey;
use crate::utils::signature_scheme_multi::SignatureSchemeMultiSignature;

#[wasm_bindgen(typescript_custom_section)]
const I_TX_SIGNER: &str = r#"
import { PublicKey } from "@iota/iota-sdk/cryptography";

export interface SignerSignatureSchemeMulti {
  sign: (tx_data_bcs: Uint8Array) => Promise<SignatureSchemeMultiSignature>;
  publicKey: () => Promise<SignatureSchemeMultiPublicKey>;
  keyId: () => string;
}
"#;

#[wasm_bindgen(typescript_custom_section)]
const ISIGNATURE_SCHEME__MULTI_SIGNATURE: &'static str = r#"
export interface SignatureSchemeMultiPublicKey {
    bytes: Uint8Array;
    keyType: any;
}

export interface SignatureSchemeMultiSignature {
    bytes: Uint8Array;
    keyType: any;
}
"#;

#[wasm_bindgen]
extern "C" {
    /// Inner signer, that will be used by [IotaCompatibleSigner].
    /// This is the incoming edge for structs/classes that implement `Signer<SignatureSchemeMulti>` in JS/TS.
    #[derive(Clone)]
    #[wasm_bindgen(typescript_type = "SignerSignatureSchemeMulti")]
    pub type WasmSignerSignatureSchemeMulti;

    #[wasm_bindgen(method, structural, catch)]
    // pub async fn sign(this: &WasmSignerSignatureSchemeMulti, tx_data: Vec<u8>) -> Result<JsString>;
    pub async fn sign(this: &WasmSignerSignatureSchemeMulti, tx_data: Vec<u8>) -> Result<JsValue>;

    #[wasm_bindgen(js_name = "publicKey", method, structural, catch)]
    pub async fn public_key(this: &WasmSignerSignatureSchemeMulti) -> Result<JsValue>;

    #[wasm_bindgen(js_name = "keyId", method, structural)]
    pub fn key_id(this: &WasmSignerSignatureSchemeMulti) -> String;
}

// Implements traits required for `IotaCompatibleSigner` to consume `WasmSignerSignatureSchemeMulti` as an inner signer.
#[async_trait(?Send)]
impl Signer<SignatureSchemeMulti> for WasmSignerSignatureSchemeMulti {
    type KeyId = String;

    async fn sign(
        &self,
        data: &SignatureSchemeMultiInput,
    ) -> std::result::Result<SignatureSchemeMultiSignature, SecretStorageError> {
        let js_value: JsValue = self.sign(data.clone()).await.map_err(|err| {
            let details = err
                .as_string()
                .map(|v| format!("; {v}"))
                .unwrap_or_default();
            let message = format!("could not sign data{details}");
            SecretStorageError::Other(anyhow::anyhow!(message))
        })?;
        let parsed = serde_wasm_bindgen::from_value(js_value).map_err(|err| {
            let details = err.to_string();
            let message = format!("could not sign data{details}");
            SecretStorageError::Other(anyhow::anyhow!(message))
        })?;

        Ok(parsed)
    }

    async fn public_key(
        &self,
    ) -> std::result::Result<SignatureSchemeMultiPublicKey, SecretStorageError> {
        let js_value: JsValue = self.public_key().await.map_err(|err| {
            let details = err
                .as_string()
                .map(|v| format!("; {v}"))
                .unwrap_or_default();
            let message = format!("could not sign data{details}");
            SecretStorageError::Other(anyhow::anyhow!(message))
        })?;
        let parsed = serde_wasm_bindgen::from_value(js_value).map_err(|err| {
            let details = err.to_string();
            let message = format!("could not sign data{details}");
            SecretStorageError::Other(anyhow::anyhow!(message))
        })?;

        Ok(parsed)
    }

    fn key_id(&self) -> String {
        self.key_id()
    }
}
