#[derive(Clone, strum::IntoStaticStr, strum::EnumString, strum::Display)]
pub enum SignatureSchemeMultiPublicKeyType {
    P256Der,
    K256Der,
    Ed25519K256Der,
    Custom(String),
}

pub struct SignatureSchemeMultiPublicKey {
    pub bytes: Vec<u8>,
    pub public_key_type: SignatureSchemeMultiPublicKeyType,
}
