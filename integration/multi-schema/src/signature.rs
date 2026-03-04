#[derive(Clone, Eq, PartialEq, strum::IntoStaticStr, strum::EnumString, strum::Display)]
pub enum SignatureSchemeMultiSignatureType {
    P256DerEncoded,
    K256DerEncoded,
    Ed25519K256DerEncoded,
    Custom(String),
}

impl Default for SignatureSchemeMultiSignatureType {
    fn default() -> Self {
        SignatureSchemeMultiSignatureType::Ed25519K256DerEncoded
    }
}

pub struct SignatureSchemeMultiSignature {
    pub bytes: Vec<u8>,
    pub signature_type: SignatureSchemeMultiSignatureType,
}
