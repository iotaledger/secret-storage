// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::borrow::Cow;
use std::fmt::Debug;
use wasm_bindgen::JsValue;

/// Convenience wrapper for `Result<T, JsValue>`.
///
/// All exported errors must be converted to [`JsValue`] when using wasm_bindgen.
/// See: https://rustwasm.github.io/docs/wasm-bindgen/reference/types/result.html
pub type Result<T> = core::result::Result<T, JsValue>;

/// Convert an error into an idiomatic [js_sys::Error].
/// Not intended to be used directly, but rather through the [WasmResult] trait.
#[allow(dead_code)]
fn wasm_error<'a, E>(error: E) -> JsValue
where
    E: Into<WasmError<'a>>,
{
    let wasm_err: WasmError<'_> = error.into();
    JsValue::from(wasm_err)
}

/// Convenience trait to simplify `result.map_err(wasm_error)` to `result.wasm_result()`
#[allow(dead_code)]
pub trait WasmResult<T> {
    fn wasm_result(self) -> Result<T>;
}

impl<'a, T, E> WasmResult<T> for core::result::Result<T, E>
where
    E: Into<WasmError<'a>>,
{
    fn wasm_result(self) -> Result<T> {
        self.map_err(wasm_error)
    }
}

impl From<anyhow::Error> for WasmError<'_> {
    fn from(value: anyhow::Error) -> Self {
        Self {
            name: Cow::Borrowed("Generic Error"),
            message: Cow::Owned(value.to_string()),
        }
    }
}

/// Convenience struct to convert internal errors to [js_sys::Error]. Uses [std::borrow::Cow]
/// internally to avoid unnecessary clones.
///
/// This is a workaround for orphan rules so we can implement [core::convert::From] on errors from
/// dependencies.
#[derive(Debug, Clone)]
pub struct WasmError<'a> {
    pub name: Cow<'a, str>,
    pub message: Cow<'a, str>,
}

impl<'a> WasmError<'a> {
    pub fn new(name: Cow<'a, str>, message: Cow<'a, str>) -> Self {
        Self { name, message }
    }
}

/// Convert [WasmError] into [js_sys::Error] for idiomatic error handling.
impl From<WasmError<'_>> for js_sys::Error {
    fn from(error: WasmError<'_>) -> Self {
        let js_error = js_sys::Error::new(&error.message);
        js_error.set_name(&error.name);
        js_error
    }
}

/// Convert [WasmError] into [wasm_bindgen::JsValue].
impl From<WasmError<'_>> for JsValue {
    fn from(error: WasmError<'_>) -> Self {
        JsValue::from(js_sys::Error::from(error))
    }
}
