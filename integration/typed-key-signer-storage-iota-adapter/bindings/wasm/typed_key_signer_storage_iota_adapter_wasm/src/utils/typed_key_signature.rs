// Copyright 2020-2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use typed_key_signature::TypedKeySignature;
use secret_storage::SignatureScheme;

pub(crate) type TypedKeySignatureInput = <TypedKeySignature as SignatureScheme>::Input;
pub(crate) type TypedKeySignaturePublicKey = <TypedKeySignature as SignatureScheme>::PublicKey;
pub(crate) type TypedKeySignatureSignature = <TypedKeySignature as SignatureScheme>::Signature;

// Private module so the Rust name (`WasmKeyType`) differs from the emitted TypeScript name (`KeyType`),
// matching the convention in aws-kms-adapter-wasm.
mod key_type {
    use serde::Deserialize;
    use serde::Serialize;
    use tsify::Tsify;

    #[derive(Tsify, Serialize, Deserialize)]
    #[tsify(into_wasm_abi, from_wasm_abi)]
    pub enum KeyType {
        Secp256r1DerEncoded,
        Secp256k1DerEncoded,
        Ed25519DerEncoded,
        #[serde(rename = "custom")]
        Custom(String),
    }
}

pub(crate) use key_type::KeyType as WasmKeyType;

