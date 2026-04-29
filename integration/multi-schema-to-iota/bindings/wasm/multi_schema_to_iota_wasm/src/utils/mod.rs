use multi_schema::SignatureSchemeMulti;
use secret_storage::SignatureScheme;

pub(crate) mod aws;

pub(crate) type SignatureSchemeMultiInput = <SignatureSchemeMulti as SignatureScheme>::Input;
pub(crate) type SignatureSchemeMultiPublicKey =
    <SignatureSchemeMulti as SignatureScheme>::PublicKey;
pub(crate) type SignatureSchemeMultiSignature =
    <SignatureSchemeMulti as SignatureScheme>::Signature;
