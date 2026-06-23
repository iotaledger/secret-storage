// Copyright 2020-2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use js_sys::Uint8Array;
use typed_key_signature::KeyType;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsValue;

use crate::error::Result;
use crate::utils::typed_key_signature::TypedKeySignaturePublicKey;
use crate::utils::typed_key_signature::TypedKeySignatureSignature;

#[wasm_bindgen(typescript_custom_section)]
const I_TX_SIGNER: &str = r#"
type TypedKeySignatureInput = Uint8Array;
"#;

// `tsify` derives the TypeScript type name from the Rust identifier.
// Private module plus re-exporting with `Wasm` prefix keeps internal Rust names consistent.
mod key_type {
  use serde::Deserialize;
  use serde::Serialize;
  use tsify::Tsify;

  #[derive(Tsify, Serialize, Deserialize, strum::Display)]
  #[tsify(into_wasm_abi, from_wasm_abi)]
  pub enum KeyType {
    Secp256r1,
    Secp256k1,
    Ed25519,
    #[serde(rename = "custom")]
    Custom(String),
  }
}

pub use key_type::KeyType as WasmKeyType;

impl TryFrom<&KeyType> for WasmKeyType {
  type Error = JsValue;

  fn try_from(key_type: &KeyType) -> Result<Self> {
    let wasm_key_type = match key_type {
      KeyType::Secp256r1 => WasmKeyType::Secp256r1,
      KeyType::Secp256k1 => WasmKeyType::Secp256k1,
      KeyType::Ed25519 => WasmKeyType::Ed25519,
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
      WasmKeyType::Secp256r1 => KeyType::Secp256r1,
      WasmKeyType::Secp256k1 => KeyType::Secp256k1,
      WasmKeyType::Ed25519 => KeyType::Ed25519,
      WasmKeyType::Custom(value) => KeyType::Custom(value.clone()),
    };

    Ok(key_type)
  }
}

#[derive(Clone)]
#[wasm_bindgen(js_name = TypedKeySignaturePublicKey)]
pub struct WasmTypedKeySignaturePublicKey(pub(crate) TypedKeySignaturePublicKey);

#[wasm_bindgen(js_class = TypedKeySignaturePublicKey)]
impl WasmTypedKeySignaturePublicKey {
  #[wasm_bindgen(getter)]
  pub fn bytes(&self) -> Uint8Array {
    self.0.bytes().as_slice().into()
  }

  #[wasm_bindgen(getter, js_name = "keyType")]
  pub fn key_type(&self) -> Result<WasmKeyType> {
    self.0.key_type().try_into()
  }
}

#[wasm_bindgen(js_name = TypedKeySignatureSignature)]
pub struct WasmTypedKeySignatureSignature(pub(crate) TypedKeySignatureSignature);

#[wasm_bindgen(js_class = TypedKeySignatureSignature)]
impl WasmTypedKeySignatureSignature {
  #[wasm_bindgen(getter)]
  pub fn bytes(&self) -> Uint8Array {
    self.0.bytes().as_slice().into()
  }

  #[wasm_bindgen(getter, js_name = "keyType")]
  pub fn key_type(&self) -> Result<WasmKeyType> {
    self.0.key_type().try_into()
  }
}
