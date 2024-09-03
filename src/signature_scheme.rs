/// [`SignatureScheme`] is a trait that defines the public key and signature types.
pub trait SignatureScheme {
    type PublicKey;
    type Signature;
}
