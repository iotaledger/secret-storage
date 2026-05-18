use serde::Deserialize;
use serde::Serialize;

#[non_exhaustive]
#[derive(
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
    Secp256r1DerEncoded,
    Secp256k1DerEncoded,
    Ed25519DerEncoded,
    Custom(String),
}

impl Default for KeyType {
    fn default() -> Self {
        KeyType::Ed25519DerEncoded
    }
}
