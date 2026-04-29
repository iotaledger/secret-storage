// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_iota::storage::JwkStorage;
use identity_iota::storage::KeyId;
use identity_iota::storage::KeyType as IdentityKeyType;
use identity_iota::verification::jwk::Jwk;
use identity_iota::verification::jws::JwsAlgorithm;
use js_sys::Uint8Array;
use multi_schema_to_iota::IotaCompatibleKeyStorage;
use std::str::FromStr;
use wasm_bindgen::prelude::*;

use crate::wasm::export::jwk_gen_output::WasmJwkGenOutput;
use crate::wasm::import::key_storage_signature_scheme_multi::WasmKeyStorageSignatureSchemeMulti;

#[wasm_bindgen(js_name = IotaCompatibleKeyStorage)]
pub struct WasmIotaCompatibleKeyStorage(
    IotaCompatibleKeyStorage<WasmKeyStorageSignatureSchemeMulti>,
);

#[wasm_bindgen(js_class = IotaCompatibleKeyStorage)]
impl WasmIotaCompatibleKeyStorage {
    #[wasm_bindgen(constructor)]
    pub fn new(storage: WasmKeyStorageSignatureSchemeMulti) -> Self {
        Self(IotaCompatibleKeyStorage { inner: storage })
    }

    /// Implements `JwkStorage::generate`. `key_type` and `alg` are strings matching
    /// identity SDK constants (e.g. `"Ed25519"`, `"EdDSA"`).
    pub async fn generate(&self, key_type: String, alg: String) -> Result<WasmJwkGenOutput, JsValue> {
        let key_type = IdentityKeyType::new(key_type);
        let alg = JwsAlgorithm::from_str(&alg)
            .map_err(|e| JsValue::from_str(&format!("invalid JwsAlgorithm: {e}")))?;

        self
            .0
            .generate(key_type, alg)
            .await
            .map(WasmJwkGenOutput::from)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    pub async fn insert(&self, _jwk: JsValue) -> Result<String, JsValue> {
        Err(JsValue::from_str(
            "Insert operation not supported for IotaCompatibleKeyStorage.",
        ))
    }

    /// Implements `JwkStorage::sign`. `public_key` must be a plain JS object matching
    /// the JWK JSON structure.
    pub async fn sign(
        &self,
        key_id: String,
        data: &[u8],
        public_key: JsValue,
    ) -> Result<Uint8Array, JsValue> {
        let jwk: Jwk = serde_wasm_bindgen::from_value(public_key)
            .map_err(|e| JsValue::from_str(&format!("invalid Jwk: {e}")))?;

        let signature = self
            .0
            .sign(&KeyId::new(key_id), data, &jwk)
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        Ok(Uint8Array::from(signature.as_slice()))
    }

    pub async fn delete(&self, key_id: String) -> Result<(), JsValue> {
        self.0
            .delete(&KeyId::new(key_id))
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    pub async fn exists(&self, key_id: String) -> Result<bool, JsValue> {
        self.0
            .exists(&KeyId::new(key_id))
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }
}
