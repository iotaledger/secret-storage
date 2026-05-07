use secret_storage::SignatureScheme;

use crate::SignatureSchemeMultiPublicKey;
use crate::SignatureSchemeMultiSignature;

pub struct SignatureSchemeMulti;

impl SignatureScheme for SignatureSchemeMulti {
    type PublicKey = SignatureSchemeMultiPublicKey;
    type Signature = SignatureSchemeMultiSignature;
    type Input = Vec<u8>;
}
