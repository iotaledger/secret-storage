use std::error::Error;

use iota_interaction::types::crypto::PublicKey;
use iota_interaction::types::crypto::SignatureScheme as IotaSignatureScheme;
use iota_interaction::IotaKeySignature;
use pkcs8::DecodePublicKey as _;
use secret_storage::SignatureScheme;

use crate::KeySpec;

pub(crate) type SignatureSchemeInput = <IotaKeySignature as SignatureScheme>::Input;
pub(crate) type SignatureSchemePublicKey = <IotaKeySignature as SignatureScheme>::PublicKey;
pub(crate) type SignatureSchemeSignature = <IotaKeySignature as SignatureScheme>::Signature;

pub fn convert_public_key_der_to_iota_public_key(
    public_key_der: &Vec<u8>,
    key_spec: &KeySpec,
) -> Result<PublicKey, Box<dyn Error>> {
    let public_key = match key_spec {
        KeySpec::EccNistEdwards25519 => {
            let public_key_bytes =
                <ed25519::pkcs8::PublicKeyBytes as pkcs8::DecodePublicKey>::from_public_key_der(
                    &public_key_der,
                )
                .unwrap();

            PublicKey::try_from_bytes(IotaSignatureScheme::ED25519, &public_key_bytes.to_bytes())
                .unwrap()
        }
        KeySpec::EccNistP256 => {
            let decoded = p256::PublicKey::from_public_key_der(&public_key_der).unwrap();
            let sec1_bytes = decoded.to_sec1_bytes();
            let pk =
                PublicKey::try_from_bytes(IotaSignatureScheme::Secp256r1, &sec1_bytes).unwrap();

            pk
        }
        KeySpec::EccSecgP256K1 => {
            let decoded = k256::PublicKey::from_public_key_der(&public_key_der).unwrap();
            let sec1_bytes = decoded.to_sec1_bytes();
            let pk =
                PublicKey::try_from_bytes(IotaSignatureScheme::Secp256k1, &sec1_bytes).unwrap();

            pk
        }
    };

    Ok(public_key)
}
