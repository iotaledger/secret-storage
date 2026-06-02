// Copyright 2020-2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use serde::Deserialize;
use serde::Serialize;

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
    Ed25519DerEncoded,
    Secp256k1DerEncoded,
    Secp256r1DerEncoded,
    Custom(String),
}
