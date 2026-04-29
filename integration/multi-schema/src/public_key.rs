use serde::Deserialize;
use serde::Serialize;

use crate::KeyType;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SignatureSchemeMultiPublicKey {
    bytes: Vec<u8>,
    key_type: KeyType,
}

impl SignatureSchemeMultiPublicKey {
    pub fn new(bytes: Vec<u8>, key_type: KeyType) -> Self {
        Self { bytes, key_type }
    }

    pub fn bytes(&self) -> &Vec<u8> {
        &self.bytes
    }

    pub fn key_type(&self) -> &KeyType {
        &self.key_type
    }
}
