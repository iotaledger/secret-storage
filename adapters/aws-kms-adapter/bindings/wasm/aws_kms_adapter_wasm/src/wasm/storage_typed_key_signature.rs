// Copyright 2020-2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use aws_kms_adapter::AwsKmsConfig;
use aws_kms_adapter::AwsKmsKeyOptions;
use aws_kms_adapter::AwsKmsStorage;
use aws_sdk_kms::Client;
use secret_storage::KeyDelete as _;
use secret_storage::KeyExist;
use secret_storage::KeyGenerate;
use secret_storage::KeyGet as _;
use secret_storage::KeySignWithOptions;
use wasm_bindgen::prelude::*;

use crate::error::Result;
use crate::error::WasmResult as _;
use crate::utils::aws::StaticCredentials;
use crate::utils::aws::WasmHttpClient;
use crate::utils::aws::WasmSleep;
use crate::utils::aws::WasmTimeSource;
use crate::wasm::typed_key_signature::WasmKeyType;
use crate::wasm::typed_key_signature::WasmTypedKeySignaturePublicKey;
use crate::wasm::signer_typed_key_signature::WasmSignerTypedKeySignature;

#[wasm_bindgen(js_name = AwsKmsStorage)]
pub struct WasmAwsKmsStorage(AwsKmsStorage);

// Implement storage traits from `secret-storage` traits for WASM storage
#[wasm_bindgen(js_class = AwsKmsStorage)]
impl WasmAwsKmsStorage {
  #[wasm_bindgen(js_name = create)]
  pub async fn new(
    region: String,
    access_key_id: String,
    secret_access_key: String,
    session_token: Option<String>,
  ) -> Result<Self> {
    let http_client = WasmHttpClient::new(reqwest::Client::new());

    let credentials = StaticCredentials::new(access_key_id, secret_access_key, session_token);
    let builder = aws_config::defaults(aws_config::BehaviorVersion::latest())
      .credentials_provider(credentials)
      .region(aws_sdk_kms::config::Region::new(region.clone()))
      .time_source(WasmTimeSource)
      .sleep_impl(WasmSleep)
      .http_client(http_client);

    let aws_config = builder.load().await;
    let client = Client::new(&aws_config);

    let inner_storage = AwsKmsStorage::from_client(
      client,
      AwsKmsConfig {
        region,
        key_options: AwsKmsKeyOptions::default(),
      },
    )
    .await
    .map_err(|e| JsValue::from_str(&e.to_string()))?;

    Ok(Self(inner_storage))
  }
}

#[wasm_bindgen]
pub struct NewKeyData {
  pub(crate) key_id: String,
  pub(crate) public_key: WasmTypedKeySignaturePublicKey,
}

impl NewKeyData {
  pub(crate) fn new(key_id: String, public_key: WasmTypedKeySignaturePublicKey) -> Self {
    Self { key_id, public_key }
  }
}

#[wasm_bindgen]
impl NewKeyData {
  #[wasm_bindgen(getter)]
  pub fn key_id(&self) -> String {
    self.key_id.clone()
  }

  #[wasm_bindgen(getter)]
  pub fn public_key(&self) -> WasmTypedKeySignaturePublicKey {
    self.public_key.clone()
  }
}

// Implements `KeyGenerate<TypedKeySignature, String>` forWASM storage
#[wasm_bindgen(js_class = AwsKmsStorage)]
impl WasmAwsKmsStorage {
  #[wasm_bindgen(js_name = "generateKeyWithOptions")]
  pub async fn generate_key_with_options(&self, options: WasmKeyType) -> Result<NewKeyData> {
    self
      .0
      .generate_key_with_options((&options).try_into().unwrap())
      .await
      .map(|(key_id, pub_key)| NewKeyData::new(key_id, WasmTypedKeySignaturePublicKey(pub_key)))
      .wasm_result()
  }
}

// Implements `KeyGet<TypedKeySignature, String>` forWASM storage
#[wasm_bindgen(js_class = AwsKmsStorage)]
impl WasmAwsKmsStorage {
  #[wasm_bindgen(js_name = "publicKey")]
  pub async fn public_key(&self, key_id: String) -> Result<WasmTypedKeySignaturePublicKey> {
    self
      .0
      .public_key(&key_id)
      .await
      .map(WasmTypedKeySignaturePublicKey)
      .wasm_result()
  }
}

// Implements `KeyDelete<String>` forWASM storage
#[wasm_bindgen(js_class = AwsKmsStorage)]
impl WasmAwsKmsStorage {
  pub async fn delete(&self, key_id: String) -> Result<()> {
    self.0.delete(&key_id).await.wasm_result()
  }
}

// Implements `KeyExist<String>` forWASM storage
#[wasm_bindgen(js_class = AwsKmsStorage)]
impl WasmAwsKmsStorage {
  pub async fn exist(&self, key_id: String) -> Result<bool> {
    self.0.exist(&key_id).await.wasm_result()
  }
}

// Implements `KeySignWithOptions<TypedKeySignature, String>` forWASM storage
#[wasm_bindgen(js_class = AwsKmsStorage)]
impl WasmAwsKmsStorage {
  #[wasm_bindgen(js_name = "getSignerWithOptions")]
  pub fn get_signer_with_options(
    &self,
    key_id: String,
    signature_type: &WasmKeyType,
  ) -> Result<WasmSignerTypedKeySignature> {
    self
      .0
      .get_signer_with_options(&key_id, &signature_type.try_into().unwrap())
      .map(WasmSignerTypedKeySignature)
      .wasm_result()
  }
}
