// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_iota::verification::jwk::Jwk;
use wasm_bindgen::prelude::*;

// TypeScript definitions for the public fields of a JSON Web Key (JWK).
// Compatible with `IJwkParams` from `@iota/identity-wasm`.

#[wasm_bindgen(typescript_custom_section)]
const JWK_PUBLIC_TYPES: &str = r#"
/** Base fields common to all JSON Web Keys (RFC 7517). */
export interface JwkBase {
    kty: string;
    use?: string;
    key_ops?: string[];
    alg?: string;
    kid?: string;
    x5u?: string;
    x5c?: string[];
    x5t?: string;
    x5t_S256?: string;
}

/** Public EC key parameters (RFC 7518 §6.2). No private key field (`d`). */
export interface PublicJwkParamsEc {
    crv: string;
    x: string;
    y: string;
}

/** Public OKP key parameters (RFC 8037). No private key field (`d`). */
export interface PublicJwkParamsOkp {
    crv: string;
    x: string;
}

/** A public EC JSON Web Key. */
export interface PublicJwkEc extends JwkBase, PublicJwkParamsEc {
    kty: "EC";
}

/** A public OKP JSON Web Key. */
export interface PublicJwkOkp extends JwkBase, PublicJwkParamsOkp {
    kty: "OKP";
}

/** A public JSON Web Key — either EC or OKP. */
export type PublicJwk = PublicJwkEc | PublicJwkOkp;
"#;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "PublicJwk")]
    pub type WasmPublicJwk;
}

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
