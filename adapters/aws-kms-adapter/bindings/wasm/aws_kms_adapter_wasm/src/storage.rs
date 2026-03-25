use aws_kms_adapter::AwsKmsConfig;
use aws_kms_adapter::AwsKmsKeyOptions;
use aws_kms_adapter::AwsKmsStorage;
use aws_sdk_kms::Client;
use secret_storage::KeyGet as _;
use wasm_bindgen::prelude::*;

use crate::utils::aws::StaticCredentials;
use crate::utils::aws::WasmHttpClient;
use crate::utils::aws::WasmSleep;
use crate::utils::aws::WasmTimeSource;

#[wasm_bindgen(js_name = AwsKmsStorage)]
pub struct WasmAwsKmsStorage(AwsKmsStorage);

#[wasm_bindgen(js_class = AwsKmsStorage)]
impl WasmAwsKmsStorage {
  #[wasm_bindgen(js_name = create)]
  pub async fn new(
    region: String,
    access_key_id: String,
    secret_access_key: String,
    session_token: Option<String>,
  ) -> Result<Self, JsValue> {
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

  pub async fn public_key(&self, key_id: String) -> Result<Vec<u8>, JsValue> {
    let ms_public_key = self
      .0
      .public_key(&key_id)
      .await
      .map_err(|e| JsValue::from_str(&e.to_string()))?;

    Ok(ms_public_key.bytes().clone())
  }

}
