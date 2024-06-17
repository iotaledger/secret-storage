/// KeySignatureSet is a trait that defines the public key and signature types.
pub trait KeySignatureTypes {
    type PublicKey: AsRef<[u8]>;
    type Signature: AsRef<[u8]>;
}
