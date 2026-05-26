// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_iota::storage::JwkGenOutput;
use identity_iota::storage::KeyId;
use serde::Serialize as _;
use wasm_bindgen::prelude::*;

use super::jwk::WasmJwk;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[wasm_bindgen(js_name = JwkGenOutput)]
pub struct WasmJwkGenOutput(pub(crate) JwkGenOutput);

#[wasm_bindgen(js_class = JwkGenOutput)]
impl WasmJwkGenOutput {
    #[wasm_bindgen(constructor)]
    pub fn new(key_id: String, jwk: &WasmJwk) -> Self {
        Self(JwkGenOutput::new(KeyId::new(key_id), jwk.0.clone()))
    }

    /// Returns the generated public {@link Jwk}.
    #[wasm_bindgen]
    pub fn jwk(&self) -> WasmJwk {
        WasmJwk(self.0.jwk.clone())
    }

    /// Returns the key id of the generated {@link Jwk}.
    #[wasm_bindgen(js_name = keyId)]
    pub fn key_id(&self) -> String {
        self.0.key_id.clone().into()
    }

    #[wasm_bindgen]
    pub fn clone(&self) -> WasmJwkGenOutput {
        WasmJwkGenOutput(self.0.clone())
    }

    /// Returns a JSON-serializable representation compatible with identity WASM's `into_serde()`.
    #[wasm_bindgen(js_name = toJSON)]
    pub fn to_json(&self) -> Result<JsValue, JsValue> {
        let serializer = serde_wasm_bindgen::Serializer::json_compatible();
        self.0
            .serialize(&serializer)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    #[wasm_bindgen(js_name = toString)]
    pub fn to_string(&self) -> String {
        serde_json::to_string(&self.0).unwrap_or_default()
    }
}

impl From<JwkGenOutput> for WasmJwkGenOutput {
    fn from(value: JwkGenOutput) -> Self {
        WasmJwkGenOutput(value)
    }
}
