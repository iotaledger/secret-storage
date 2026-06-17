// Copyright 2020-2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use serde::Deserialize;
use serde::Serialize;

/// Identifies the signing algorithm of a key pair. Does not describe byte encoding —
/// see [`TypedKeySignaturePublicKey::bytes`] and [`TypedKeySignatureSignature::bytes`] for encoding details.
#[non_exhaustive]
#[derive(
    Default,
    Serialize,
    Deserialize,
    Debug,
    Clone,
    Eq,
    PartialEq,
    strum::IntoStaticStr,
    strum::EnumString,
    strum::Display,
    strum::VariantNames,
)]
pub enum KeyType {
    #[default]
    Ed25519,
    Secp256k1,
    Secp256r1,
    Custom(String),
}
