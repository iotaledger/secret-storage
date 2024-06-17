pub trait KeySignatureSet {
    type PublicKey: AsRef<[u8]>;
    type Signature: AsRef<[u8]>;
}
