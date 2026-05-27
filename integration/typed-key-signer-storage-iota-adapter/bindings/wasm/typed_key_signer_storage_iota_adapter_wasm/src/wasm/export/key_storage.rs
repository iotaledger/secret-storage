// Copyright 2020-2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use anyhow::anyhow;
use fastcrypto::traits::EncodeDecodeBase64;
use iota_interaction::IotaKeySignature;
use secret_storage::KeyDelete;
use secret_storage::KeyExist;
use secret_storage::KeyGenerate;
use secret_storage::KeyGet;
use secret_storage::KeySignWithOptions;
use typed_key_signature::KeyType;
use typed_key_signer_storage_iota_adapter::IotaCompatibleKeyStorage;
use wasm_bindgen::prelude::*;

use crate::error::Result;
use crate::error::WasmResult as _;
use crate::utils::typed_key_signature::WasmKeyType;
use crate::wasm::export::transaction_signer::WasmIotaCompatibleSigner;
use crate::wasm::import::key_storage_typed_key_signature::WasmKeyStorageTypedKeySignature;

#[wasm_bindgen(getter_with_clone)]
pub struct GenerateKeyOutput {
    pub key_id: String,
    pub public_key: String,
}

#[wasm_bindgen(js_name = IotaCompatibleKeyStorage)]
pub struct WasmIotaCompatibleKeyStorage(IotaCompatibleKeyStorage<WasmKeyStorageTypedKeySignature>);

#[wasm_bindgen(js_class = IotaCompatibleKeyStorage)]
impl WasmIotaCompatibleKeyStorage {
    #[wasm_bindgen(constructor)]
    pub fn new(storage: WasmKeyStorageTypedKeySignature) -> Self {
        Self(IotaCompatibleKeyStorage { inner: storage })
    }

    #[wasm_bindgen(js_name = generateKey)]
    pub async fn generate_key(&self, key_type: WasmKeyType) -> Result<GenerateKeyOutput> {
        let options = wasm_key_type_to_typed(key_type);

        let (key_id, public_key) =
            KeyGenerate::<IotaKeySignature, String>::generate_key_with_options(&self.0, options)
                .await
                .map_err(|e| anyhow!("{e}"))
                .wasm_result()?;

        Ok(GenerateKeyOutput {
            key_id,
            public_key: public_key.encode_base64(),
        })
    }

    #[wasm_bindgen(js_name = getSignerWithOptions)]
    pub fn get_signer_with_options(
        &self,
        key_id: String,
        key_type: WasmKeyType,
    ) -> Result<WasmIotaCompatibleSigner> {
        let options = wasm_key_type_to_typed(key_type);

        let signer =
            KeySignWithOptions::<IotaKeySignature, String>::get_signer_with_options(
                &self.0,
                &key_id,
                &options,
            )
            .map_err(|e| anyhow!("{e}"))
            .wasm_result()?;

        Ok(WasmIotaCompatibleSigner(signer))
    }

    #[wasm_bindgen(js_name = publicKey)]
    pub async fn public_key(&self, key_id: String) -> Result<String> {
        KeyGet::<IotaKeySignature, String>::public_key(&self.0, &key_id)
            .await
            .map(|pk| pk.encode_base64())
            .map_err(|e| anyhow!("{e}"))
            .wasm_result()
    }

    pub async fn delete(&self, key_id: String) -> Result<()> {
        KeyDelete::<String>::delete(&self.0, &key_id)
            .await
            .map_err(|e| anyhow!("{e}"))
            .wasm_result()
    }

    pub async fn exist(&self, key_id: String) -> Result<bool> {
        KeyExist::<String>::exist(&self.0, &key_id)
            .await
            .map_err(|e| anyhow!("{e}"))
            .wasm_result()
    }
}

fn wasm_key_type_to_typed(wt: WasmKeyType) -> KeyType {
    match wt {
        WasmKeyType::Secp256r1DerEncoded => KeyType::Secp256r1DerEncoded,
        WasmKeyType::Secp256k1DerEncoded => KeyType::Secp256k1DerEncoded,
        WasmKeyType::Ed25519DerEncoded => KeyType::Ed25519DerEncoded,
        WasmKeyType::Custom(s) => KeyType::Custom(s),
    }
}
