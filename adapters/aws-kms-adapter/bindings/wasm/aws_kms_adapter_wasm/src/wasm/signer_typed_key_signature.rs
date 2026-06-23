// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use aws_kms_adapter::AwsKmsSigner;
use js_sys::Uint8Array;
use secret_storage::Signer;
use wasm_bindgen::prelude::*;

use crate::error::Result;
use crate::error::WasmResult as _;
use crate::wasm::typed_key_signature::WasmTypedKeySignaturePublicKey;
use crate::wasm::typed_key_signature::WasmTypedKeySignatureSignature;

#[wasm_bindgen(js_name = AwsKmsSigner)]
pub struct WasmSignerTypedKeySignature(pub(crate) AwsKmsSigner);

// Implement `Signer<TypedKeySignature>` behavior for the WASM signer.
#[wasm_bindgen(js_class = AwsKmsSigner)]
impl WasmSignerTypedKeySignature {
  pub async fn sign(
    &self,
    #[wasm_bindgen(unchecked_param_type = "TypedKeySignatureInput")] data: &Uint8Array,
  ) -> Result<WasmTypedKeySignatureSignature> {
    self
      .0
      .sign(&data.to_vec())
      .await
      .map(WasmTypedKeySignatureSignature)
      .wasm_result()
  }

  #[wasm_bindgen(js_name = "publicKey")]
  pub async fn public_key(&self) -> Result<WasmTypedKeySignaturePublicKey> {
    self
      .0
      .public_key()
      .await
      .map(WasmTypedKeySignaturePublicKey)
      .wasm_result()
  }

  #[wasm_bindgen(js_name = "keyId")]
  pub fn key_id(&self) -> String {
    self.0.key_id()
  }
}
