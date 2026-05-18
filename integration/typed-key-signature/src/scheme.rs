use secret_storage::SignatureScheme;

use crate::TypedKeySignaturePublicKey;
use crate::TypedKeySignatureSignature;

pub struct TypedKeySignature;

impl SignatureScheme for TypedKeySignature {
    type PublicKey = TypedKeySignaturePublicKey;
    type Signature = TypedKeySignatureSignature;
    type Input = Vec<u8>;
}
