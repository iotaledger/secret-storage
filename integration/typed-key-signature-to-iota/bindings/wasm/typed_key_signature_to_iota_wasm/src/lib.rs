// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod error;
mod utils;
mod wasm;

use wasm_bindgen::prelude::*;

pub use wasm::export::jwk_storage::*;
pub use wasm::export::transaction_signer::*;

#[wasm_bindgen]
pub fn greet(name: String) -> String {
    format!("Hello, {name}!")
}
