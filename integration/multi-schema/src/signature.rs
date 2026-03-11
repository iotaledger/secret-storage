use crate::KeyType;

pub struct SignatureSchemeMultiSignature {
    bytes: Vec<u8>,
    key_type: KeyType,
}

impl SignatureSchemeMultiSignature {
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
