// Copyright 2020-2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use anyhow::anyhow;
use fastcrypto::traits::EncodeDecodeBase64;
use identity_iota::iota_interaction::IotaKeySignature;
use typed_key_signature_to_iota::IotaCompatibleSigner;
use secret_storage::Signer;
use wasm_bindgen::prelude::*;

use crate::error::Result;
use crate::error::WasmResult as _;
use crate::wasm::import::signer_typed_key_signature::WasmSignerTypedKeySignature;

#[wasm_bindgen(js_name = IotaCompatibleSigner)]
pub struct WasmIotaCompatibleSigner(IotaCompatibleSigner<WasmSignerTypedKeySignature>);

#[wasm_bindgen(js_class = IotaCompatibleSigner)]
impl WasmIotaCompatibleSigner {
    #[wasm_bindgen(constructor)]
    pub fn new(signer: WasmSignerTypedKeySignature) -> Self {
        Self(IotaCompatibleSigner::new(signer))
    }
}

/// Implementation to support `TransactionSigner` behavior.
#[wasm_bindgen(js_class = IotaCompatibleSigner)]
impl WasmIotaCompatibleSigner {
    #[wasm_bindgen]
    pub async fn sign(&self, tx_data_bcs: &[u8]) -> Result<String> {
        let tx_data = bcs::from_bytes(tx_data_bcs).map_err(|e| JsError::new(&e.to_string()))?;
        Signer::<IotaKeySignature>::sign(&self.0, &tx_data)
            .await
            .map(|sig| sig.encode_base64())
            .map_err(|e| anyhow!("Failed to sign data: {e}"))
            .wasm_result()
    }

    #[wasm_bindgen(js_name = publicKey)]
    pub async fn public_key(&self) -> Result<String> {
        Signer::<IotaKeySignature>::public_key(&self.0)
            .await
            .map(|pk| pk.encode_base64())
            .map_err(|e| anyhow!("Failed to get public key: {e}"))
            .wasm_result()
    }

    #[wasm_bindgen(js_name = iotaPublicKeyBytes)]
    pub async fn iota_public_key_bytes(&self) -> Result<Vec<u8>> {
        let pk = Signer::<IotaKeySignature>::public_key(&self.0)
            .await
            .map_err(|e| anyhow!("Failed to get public key: {e}"))
            .wasm_result()?;
        let mut bytes = Vec::with_capacity(1 + pk.as_ref().len());
        bytes.push(pk.flag());
        bytes.extend_from_slice(pk.as_ref());
        Ok(bytes)
    }

    #[wasm_bindgen(js_name = keyId)]
    pub fn key_id(&self) -> String {
        self.0.key_id()
        // todo!()
    }
}
