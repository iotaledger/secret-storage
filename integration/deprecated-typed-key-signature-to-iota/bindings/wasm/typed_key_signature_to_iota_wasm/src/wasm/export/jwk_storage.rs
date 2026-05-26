// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_iota::storage::JwkStorage;
use identity_iota::storage::KeyId;
use identity_iota::storage::KeyType as IdentityKeyType;
use identity_iota::verification::jwk::Jwk;
use identity_iota::verification::jws::JwsAlgorithm;
use js_sys::Uint8Array;
use typed_key_signature_to_iota::IotaCompatibleKeyStorage;
use std::str::FromStr;
use wasm_bindgen::prelude::*;

use crate::wasm::export::jwk::WasmPublicJwk;
use crate::wasm::export::jwk_gen_output::WasmJwkGenOutput;
use crate::wasm::import::key_storage_typed_key_signature::WasmKeyStorageTypedKeySignature;

#[wasm_bindgen(js_name = IotaCompatibleKeyStorage)]
pub struct WasmIotaCompatibleKeyStorage(
    IotaCompatibleKeyStorage<WasmKeyStorageTypedKeySignature>,
);

/// Implementation to support `JwkStorage` behavior.
#[wasm_bindgen(js_class = IotaCompatibleKeyStorage)]
impl WasmIotaCompatibleKeyStorage {
    #[wasm_bindgen(constructor)]
    pub fn new(storage: WasmKeyStorageTypedKeySignature) -> Self {
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

    /// Returns the public key for `key_id` as a plain JWK JS object.
    #[wasm_bindgen(js_name = publicKeyJwk)]
    pub async fn public_key_jwk(&self, key_id: String) -> Result<WasmPublicJwk, JsValue> {
        let jwk = self
            .0
            .public_key_jwk(&key_id)
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        // serde_wasm_bindgen does not support #[serde(flatten)], which Jwk uses for its
        // params field — kty would be dropped. Serialize via serde_json first, then parse.
        let json = serde_json::to_string(&jwk)
            .map_err(|e| JsValue::from_str(&format!("failed to serialize JWK: {e}")))?;
        js_sys::JSON::parse(&json)
            .map(|v| v.unchecked_into::<WasmPublicJwk>())
            .map_err(|e| e)
    }

    pub async fn insert(&self, _jwk: JsValue) -> Result<String, JsValue> {
        Err(JsValue::from_str(
            "Insert operation not supported for IotaCompatibleKeyStorage.",
        ))
    }

    /// Implements `JwkStorage::sign`.
    /// `public_key` is a `Jwk` from `identity-wasm` — passed through JS to cross the WASM memory boundary.
    pub async fn sign(
        &self,
        key_id: String,
        data: &[u8],
        #[wasm_bindgen(unchecked_param_type = "Jwk")] public_key: JsValue,
    ) -> Result<Uint8Array, JsValue> {
        // Call `toJSON` to copy JWK field values from `identity-wasm`'s WASM memory into a plain JS object.
        let to_json = js_sys::Reflect::get(&public_key, &JsValue::from_str("toJSON"))
            .map_err(|e| JsValue::from_str(&format!("invalid Jwk: no toJSON: {e:?}")))?;
        let json_val = js_sys::Function::unchecked_from_js(to_json)
            .call0(&public_key)
            .map_err(|e| JsValue::from_str(&format!("invalid Jwk: toJSON failed: {e:?}")))?;
        let json_str = js_sys::JSON::stringify(&json_val)
            .map(|s| s.as_string().unwrap_or_default())
            .map_err(|e| JsValue::from_str(&format!("invalid Jwk: JSON.stringify failed: {e:?}")))?;
        // Deserialize with `serde_json` instead of `serde_wasm_bindgen`, as serialization is done with
        // `#[serde(flatten)]`, which is not supported by `serde_wasm_bindgen`.
        let jwk: Jwk = serde_json::from_str(&json_str)
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
