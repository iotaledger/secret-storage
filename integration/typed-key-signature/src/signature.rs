// Copyright 2020-2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use serde::Deserialize;
use serde::Serialize;

use crate::KeyType;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct TypedKeySignatureSignature {
    bytes: Vec<u8>,
    key_type: KeyType,
}

impl TypedKeySignatureSignature {
    pub fn new(bytes: Vec<u8>, key_type: KeyType) -> Self {
        Self { bytes, key_type }
    }

    /// Returns the raw signature bytes. Encoding depends on the key type:
    /// - `Secp256k1` / `Secp256r1`: DER-encoded (ANSI X9.62 / RFC 3279)
    /// - `Ed25519`: raw 64-byte format (RFC 8032)
    pub fn bytes(&self) -> &Vec<u8> {
        &self.bytes
    }

    pub fn key_type(&self) -> &KeyType {
        &self.key_type
    }
}
