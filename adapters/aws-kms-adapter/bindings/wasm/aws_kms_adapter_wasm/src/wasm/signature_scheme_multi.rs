// Copyright 2020-2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use js_sys::Uint8Array;
use multi_schema::KeyType;
use serde::Deserialize;
use serde::Serialize;
use tsify::Tsify;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsValue;

use crate::error::Result;
use crate::utils::signature_scheme_multi::SignatureSchemeMultiPublicKey;
use crate::utils::signature_scheme_multi::SignatureSchemeMultiSignature;

#[wasm_bindgen(typescript_custom_section)]
const I_TX_SIGNER: &str = r#"
type SignatureSchemeMultiInput = Uint8Array;
"#;

#[derive(Tsify, Serialize, Deserialize, strum::Display)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub enum WasmKeyType {
  P256DerEncoded,
  K256DerEncoded,
  Ed25519DerEncoded,
  #[serde(rename = "custom")]
  Custom(String),
}

impl TryFrom<&KeyType> for WasmKeyType {
  type Error = JsValue;

  fn try_from(key_type: &KeyType) -> Result<Self> {
    let wasm_key_type = match key_type {
      KeyType::P256DerEncoded => WasmKeyType::P256DerEncoded,
      KeyType::K256DerEncoded => WasmKeyType::K256DerEncoded,
      KeyType::Ed25519DerEncoded => WasmKeyType::Ed25519DerEncoded,
      KeyType::Custom(value) => WasmKeyType::Custom(value.clone()),
      other => {
        return Err(JsValue::from_str(&format!("Key type '{other}' not supported.")));
      }
    };

    Ok(wasm_key_type)
  }
}

impl TryFrom<&WasmKeyType> for KeyType {
  type Error = JsValue;

  fn try_from(wasm_key_type: &WasmKeyType) -> Result<Self> {
    let key_type = match wasm_key_type {
      WasmKeyType::P256DerEncoded => KeyType::P256DerEncoded,
      WasmKeyType::K256DerEncoded => KeyType::K256DerEncoded,
      WasmKeyType::Ed25519DerEncoded => KeyType::Ed25519DerEncoded,
      WasmKeyType::Custom(value) => KeyType::Custom(value.clone()),
    };

    Ok(key_type)
  }
}

#[derive(Clone)]
#[wasm_bindgen(js_name = SignatureSchemeMultiPublicKey)]
pub struct WasmSignatureSchemeMultiPublicKey(pub(crate) SignatureSchemeMultiPublicKey);

#[wasm_bindgen(js_class = SignatureSchemeMultiPublicKey)]
impl WasmSignatureSchemeMultiPublicKey {
  #[wasm_bindgen(getter)]
  pub fn bytes(&self) -> Uint8Array {
    self.0.bytes().as_slice().into()
  }

  #[wasm_bindgen(getter, js_name = "keyType")]
  pub fn key_type(&self) -> Result<WasmKeyType> {
    self.0.key_type().try_into()
  }
}

#[wasm_bindgen(js_name = SignatureSchemeMultiSignature)]
pub struct WasmSignatureSchemeMultiSignature(pub(crate) SignatureSchemeMultiSignature);

#[wasm_bindgen(js_class = SignatureSchemeMultiSignature)]
impl WasmSignatureSchemeMultiSignature {
  #[wasm_bindgen(getter)]
  pub fn bytes(&self) -> Uint8Array {
    self.0.bytes().as_slice().into()
  }

  #[wasm_bindgen(getter, js_name = "keyType")]
  pub fn key_type(&self) -> Result<WasmKeyType> {
    self.0.key_type().try_into()
  }
}
