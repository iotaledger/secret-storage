// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_iota::verification::jwk::Jwk;
use wasm_bindgen::prelude::*;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
#[wasm_bindgen(js_name = Jwk)]
pub struct WasmJwk(pub(crate) Jwk);

#[wasm_bindgen(js_class = Jwk)]
impl WasmJwk {
    /// Returns a clone of the {@link Jwk} with all private key components unset.
    #[wasm_bindgen(js_name = toPublic)]
    pub fn to_public(&self) -> Option<WasmJwk> {
        self.0.to_public().map(WasmJwk)
    }

    /// Returns the value for the algorithm property (alg).
    #[wasm_bindgen]
    pub fn alg(&self) -> Option<String> {
        self.0.alg().map(ToOwned::to_owned)
    }
}

impl From<Jwk> for WasmJwk {
    fn from(jwk: Jwk) -> Self {
        WasmJwk(jwk)
    }
}

impl From<WasmJwk> for Jwk {
    fn from(wasm: WasmJwk) -> Self {
        wasm.0
    }
}
