// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;
use std::task::Context;
use std::task::Poll;

use aws_credential_types::provider::future;
use aws_credential_types::provider::ProvideCredentials;
use aws_credential_types::Credentials;
use aws_sdk_kms::config::AsyncSleep;
use aws_sdk_kms::config::Sleep;
use aws_smithy_async::time::TimeSource;
use aws_smithy_runtime_api::client::connector_metadata::ConnectorMetadata;
use aws_smithy_runtime_api::client::http::HttpClient;
use aws_smithy_runtime_api::client::http::HttpConnector;
use aws_smithy_runtime_api::client::http::HttpConnectorFuture;
use aws_smithy_runtime_api::client::http::HttpConnectorSettings;
use aws_smithy_runtime_api::client::http::SharedHttpConnector;
use aws_smithy_runtime_api::client::orchestrator::HttpRequest;
use aws_smithy_runtime_api::client::result::ConnectorError;
use aws_smithy_runtime_api::client::runtime_components::RuntimeComponents;
use aws_smithy_runtime_api::http::Response;
use aws_smithy_runtime_api::shared::IntoShared;
use aws_smithy_types::body::SdkBody;
use aws_smithy_types::retry::ErrorKind;
use http_1x::HeaderName;
use http_1x::Method;
use reqwest::Client as ReqwestClient;
use wasm_bindgen::JsCast;
use wasm_bindgen::JsValue;

/// Wraps a `Future` and asserts it is `Send`.
///
/// # Safety
/// `wasm32-unknown-unknown` is single-threaded, so no data can actually
/// be sent across threads.  The assertion is therefore safe on this target.
pub(crate) struct AssertSend<F>(pub(crate) F);
unsafe impl<F> Send for AssertSend<F> {}
// SAFETY: wasm32-unknown-unknown is single-threaded; no concurrent access is possible.
unsafe impl<F> Sync for AssertSend<F> {}
impl<F: Future> Future for AssertSend<F> {
  type Output = F::Output;
  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<F::Output> {
    // SAFETY: we only project to the inner field, which is pinned as part of self.
    unsafe { self.map_unchecked_mut(|s| &mut s.0) }.poll(cx)
  }
}

/// HTTP client for use in wasm32-unknown-unknown environments.
///
/// Routes AWS SDK HTTP requests through the browser's Fetch API via `reqwest`.
#[derive(Clone, Debug)]
pub struct WasmHttpClient(ReqwestClient);

impl WasmHttpClient {
  pub fn new(client: ReqwestClient) -> Self {
    WasmHttpClient(client)
  }
}

impl HttpConnector for WasmHttpClient {
  fn call(&self, request: HttpRequest) -> HttpConnectorFuture {
    let client = self.0.clone();

    HttpConnectorFuture::new(AssertSend(async move {
      let method = Method::from_str(request.method())
        .map_err(|e| ConnectorError::other(Box::new(e), None))?;

      let mut request_builder = client.request(method, request.uri().to_string());

      for (name, value) in request.headers().iter() {
        let header_name = HeaderName::from_str(name)
          .map_err(|e| ConnectorError::other(Box::new(e), None))?;
        let header_value = value
          .to_string()
          .parse::<reqwest::header::HeaderValue>()
          .map_err(|e| ConnectorError::other(Box::new(e), None))?;
        request_builder = request_builder.header(header_name, header_value);
      }

      if let Some(body_bytes) = request.body().bytes() {
        request_builder = request_builder.body(body_bytes.to_vec());
      }

      let reqwest_request = request_builder
        .build()
        .map_err(|e| ConnectorError::other(e.into(), Some(ErrorKind::ClientError)))?;

      let response = client
        .execute(reqwest_request)
        .await
        .map_err(|e| ConnectorError::other(e.into(), Some(ErrorKind::ClientError)))?;

      let status = response.status();
      let headers = response.headers().clone();
      let body_bytes = response
        .bytes()
        .await
        .map_err(|e| ConnectorError::other(e.into(), Some(ErrorKind::ClientError)))?;

      let sdk_body = SdkBody::from(body_bytes.as_ref());

      let mut http_response_builder = http_1x::Response::builder().status(status.as_u16());
      for (name, value) in headers.iter() {
        http_response_builder = http_response_builder.header(name.as_str(), value.as_bytes());
      }
      let http_response = http_response_builder
        .body(sdk_body)
        .map_err(|e| ConnectorError::other(Box::new(e), None))?;

      Response::try_from(http_response).map_err(|e| ConnectorError::other(Box::new(e), None))
    }))
  }
}

impl HttpClient for WasmHttpClient {
  fn http_connector(&self, _: &HttpConnectorSettings, _: &RuntimeComponents) -> SharedHttpConnector {
    self.clone().into_shared()
  }

  fn connector_metadata(&self) -> Option<ConnectorMetadata> {
    Some(ConnectorMetadata::new("wasm-http-client", None))
  }
}

#[derive(Debug, Clone)]
pub struct WasmTimeSource;

impl TimeSource for WasmTimeSource {
  fn now(&self) -> std::time::SystemTime {
    let millis = js_sys::Date::now() as u64;
    std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_millis(millis)
  }
}

/// A [`ProvideCredentials`] implementation that holds a fixed key pair.
#[derive(Debug)]
pub struct StaticCredentials {
  inner: Credentials,
}

impl StaticCredentials {
  /// `session_token` is required for temporary credentials (STS / SSO assumed roles).
  pub fn new(
    access_key_id: impl Into<String>,
    secret_access_key: impl Into<String>,
    session_token: Option<String>,
  ) -> Self {
    Self {
      inner: Credentials::new(access_key_id, secret_access_key, session_token, None, "static"),
    }
  }
}

impl ProvideCredentials for StaticCredentials {
  fn provide_credentials<'a>(&'a self) -> future::ProvideCredentials<'a>
  where
    Self: 'a,
  {
    future::ProvideCredentials::ready(Ok(self.inner.clone()))
  }
}

/// An [`AsyncSleep`] implementation that uses JS `setTimeout`
#[derive(Debug, Clone)]
pub struct WasmSleep;

impl AsyncSleep for WasmSleep {
  fn sleep(&self, duration: std::time::Duration) -> Sleep {
    Sleep::new(AssertSend(async move {
      let millis = duration.as_millis() as f64;
      let promise = js_sys::Promise::new(&mut |resolve, _| {
        let set_timeout = js_sys::Reflect::get(&js_sys::global(), &"setTimeout".into())
          .expect("setTimeout not found")
          .unchecked_into::<js_sys::Function>();
        set_timeout
          .call2(&JsValue::UNDEFINED, &resolve, &millis.into())
          .expect("setTimeout call failed");
      });
      wasm_bindgen_futures::JsFuture::from(promise).await.ok();
    }))
  }
}
