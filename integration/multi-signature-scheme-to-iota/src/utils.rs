use std::error::Error;

use iota_interaction::types::crypto::SignatureScheme as IotaSignatureScheme;
use multi_signature_scheme::KeyType;
use pkcs8::DecodePublicKey as _;

use iota_interaction::IotaKeySignature;
use secret_storage::SignatureScheme;

pub(crate) type SignatureSchemeIota = IotaKeySignature;
pub(crate) type SignatureSchemeIotaInput = <IotaKeySignature as SignatureScheme>::Input;
pub(crate) type SignatureSchemeIotaPublicKey = <IotaKeySignature as SignatureScheme>::PublicKey;
pub(crate) type SignatureSchemeIotaSignature = <IotaKeySignature as SignatureScheme>::Signature;

pub fn convert_public_key_der_to_iota_public_key(
    public_key_der: &Vec<u8>,
    key_type: &KeyType,
) -> Result<SignatureSchemeIotaPublicKey, Box<dyn Error>> {
    let public_key = match key_type {
        KeyType::Ed25519DerEncoded => {
            let public_key_bytes =
                <ed25519::pkcs8::PublicKeyBytes as pkcs8::DecodePublicKey>::from_public_key_der(
                    &public_key_der,
                )
                .unwrap();

            SignatureSchemeIotaPublicKey::try_from_bytes(
                IotaSignatureScheme::ED25519,
                &public_key_bytes.to_bytes(),
            )
            .unwrap()
        }
        KeyType::P256DerEncoded => {
            let decoded = p256::PublicKey::from_public_key_der(&public_key_der).unwrap();
            let sec1_bytes = decoded.to_sec1_bytes();
            let pk = SignatureSchemeIotaPublicKey::try_from_bytes(
                IotaSignatureScheme::Secp256r1,
                &sec1_bytes,
            )
            .unwrap();

            pk
        }
        KeyType::K256DerEncoded => {
            let decoded = k256::PublicKey::from_public_key_der(&public_key_der).unwrap();
            let sec1_bytes = decoded.to_sec1_bytes();
            let pk = SignatureSchemeIotaPublicKey::try_from_bytes(
                IotaSignatureScheme::Secp256k1,
                &sec1_bytes,
            )
            .unwrap();

            pk
        }
        other => panic!("unsupported public key type {other}"),
    };

    Ok(public_key)
}
