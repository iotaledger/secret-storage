use std::str::FromStr;

use async_trait::async_trait;
use identity_iota::storage::JwkGenOutput;
use identity_iota::storage::JwkStorage;
use identity_iota::storage::KeyId;
use identity_iota::storage::KeyStorageError;
use identity_iota::storage::KeyStorageErrorKind;
use identity_iota::storage::KeyStorageResult;
use identity_iota::storage::KeyType;
use identity_iota::verification::jwk::EcCurve;
use identity_iota::verification::jwk::EdCurve;
use identity_iota::verification::jwk::Jwk;
use identity_iota::verification::jwk::ToJwk;
use identity_iota::verification::jws::JwsAlgorithm;
use iota_interaction::types::crypto::PublicKey;
use k256::ecdsa::Signature as K256Signature;
use p256::ecdsa::Signature as P256Signature;
use secret_storage::KeyGenerate;

use crate::sign;
use crate::AwsKmsKeyOptions;
use crate::AwsKmsStorage;
use crate::KeySpec;
use crate::SigningAlgorithmSpec;

pub fn create_jwk_for_public_key(iota_public_key: &PublicKey) -> Jwk {
    let mut jwk = ToJwk::to_jwk(iota_public_key).unwrap();
    jwk.set_kid(jwk.thumbprint_sha256_b64());

    jwk
}

fn key_alg_mismatch_error(key_spec: &KeySpec, alg: &JwsAlgorithm) -> KeyStorageError {
    KeyStorageError::new(KeyStorageErrorKind::KeyAlgorithmMismatch).with_custom_message(format!(
        "cannot use key type `{key_spec}` with algorithm `{alg}`",
    ))
}

// TODO: remove `allow`
#[allow(dead_code)]
fn aws_kms_key_options(
    key_spec: &KeySpec,
    key_type: &KeyType,
    alg: &JwsAlgorithm,
) -> AwsKmsKeyOptions {
    AwsKmsKeyOptions {
        description: Some("IOTA AwsKmsStorage key for JOSE signing and verification".to_string()),
        policy: None, // Use default policy
        alias: None,  // No alias in the futures
        tags: vec![
            ("CreatedBy".to_string(), "aws-kms-adapter".to_string()),
            ("KeyType".to_string(), key_type.to_string()),
            ("JwsAlgorithm".to_string(), alg.to_string()),
        ],
        key_spec: Some(key_spec.clone()),
    }
}

/// Check that the key type can be used with the algorithm.
fn check_key_alg_compatibility(key_spec: &KeySpec, alg: &JwsAlgorithm) -> KeyStorageResult<()> {
    match (key_spec, &alg) {
        (KeySpec::EccNistP256, JwsAlgorithm::ES256) => Ok(()),
        (KeySpec::EccSecgP256K1, JwsAlgorithm::ES256K) => Ok(()),
        (KeySpec::EccNistEdwards25519, JwsAlgorithm::EdDSA) => Ok(()),
        _ => Err(key_alg_mismatch_error(&key_spec, &alg)),
    }
}

#[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync-storage", async_trait)]
impl JwkStorage for AwsKmsStorage {
    async fn generate(
        &self,
        key_type: KeyType,
        alg: JwsAlgorithm,
    ) -> KeyStorageResult<JwkGenOutput> {
        // check if inputs and their combinations are supported by internal types
        let _alg_spec: SigningAlgorithmSpec = alg.try_into()?;
        let key_spec = KeySpec::try_from(key_type.as_str()).map_err(|err| {
            KeyStorageError::new(KeyStorageErrorKind::UnsupportedKeyType).with_source(err)
        })?;
        check_key_alg_compatibility(&key_spec, &alg)?;

        // no predefined key, generate a new one and update config
        // consecutive calls will use the key generated here
        let options = aws_kms_key_options(&key_spec, &key_type, &alg);

        let (kms_key_id, public_key_iota) = self.generate_key_with_options(options).await.unwrap();

        let jwk = create_jwk_for_public_key(&public_key_iota);

        Ok(JwkGenOutput::new(KeyId::new(kms_key_id), jwk))
    }

    async fn insert(&self, _jwk: Jwk) -> KeyStorageResult<KeyId> {
        Err(KeyStorageError::new(KeyStorageErrorKind::Unspecified)
            .with_custom_message("inserting keys into AWS is currently not supported"))
    }

    // TODO: create and use signer instead
    async fn sign(
        &self,
        key_id: &KeyId,
        data: &[u8],
        public_key: &Jwk,
    ) -> KeyStorageResult<Vec<u8>> {
        // Extract the required alg from the given public key
        let alg = public_key
            .alg()
            .ok_or(KeyStorageErrorKind::UnsupportedSignatureAlgorithm)
            .and_then(|alg_str| {
                JwsAlgorithm::from_str(alg_str)
                    .map_err(|_| KeyStorageErrorKind::UnsupportedSignatureAlgorithm)
            })?;

        // Check that `kty` and `crv``
        match alg {
            JwsAlgorithm::ES256 => {
                let ec_params = public_key.try_ec_params().map_err(|err| {
                    KeyStorageError::new(KeyStorageErrorKind::Unspecified)
                        .with_custom_message(format!(
                            "expected a Jwk with Ec params in order to sign with {alg}"
                        ))
                        .with_source(err)
                })?;
                if ec_params.crv != EcCurve::P256.name() {
                    return Err(KeyStorageError::new(KeyStorageErrorKind::Unspecified)
                        .with_custom_message(format!(
                            "expected Jwk with Ec {} crv in order to sign with {alg}",
                            EdCurve::Ed25519
                        )));
                }
            }
            JwsAlgorithm::ES256K => {
                let ec_params = public_key.try_ec_params().map_err(|err| {
                    KeyStorageError::new(KeyStorageErrorKind::Unspecified)
                        .with_custom_message(format!(
                            "expected a Jwk with Ec params in order to sign with {alg}"
                        ))
                        .with_source(err)
                })?;
                if ec_params.crv != EcCurve::Secp256K1.name() {
                    return Err(KeyStorageError::new(KeyStorageErrorKind::Unspecified)
                        .with_custom_message(format!(
                            "expected Jwk with Ec {} crv in order to sign with {alg}",
                            EdCurve::Ed25519
                        )));
                }
            }
            JwsAlgorithm::EdDSA => {
                let okp_params = public_key.try_okp_params().map_err(|err| {
                    KeyStorageError::new(KeyStorageErrorKind::Unspecified)
                        .with_custom_message(format!(
                            "expected a Jwk with Okp params in order to sign with {alg}"
                        ))
                        .with_source(err)
                })?;
                if okp_params.crv != EdCurve::Ed25519.name() {
                    return Err(KeyStorageError::new(KeyStorageErrorKind::Unspecified)
                        .with_custom_message(format!(
                            "expected Jwk with Okp {} crv in order to sign with {alg}",
                            EdCurve::Ed25519
                        )));
                }
            }
            other => {
                return Err(KeyStorageError::new(
                    KeyStorageErrorKind::UnsupportedSignatureAlgorithm,
                )
                .with_custom_message(format!("{other} is not supported")));
            }
        };

        let alg_spec = alg.try_into()?;
        let signature = sign(&self.client, &key_id.to_string(), &data.to_vec(), &alg_spec)
            .await
            .unwrap();

        let signature = match alg {
            JwsAlgorithm::ES256 => P256Signature::from_der(&signature).unwrap().to_vec(),
            JwsAlgorithm::ES256K => K256Signature::from_der(&signature).unwrap().to_vec(),
            _ => signature,
        };

        Ok(signature)
    }

    async fn delete(&self, key_id: &KeyId) -> KeyStorageResult<()> {
        self.delete(key_id.as_str(), None).await.unwrap();
        Ok(())
    }

    async fn exists(&self, _key_id: &KeyId) -> KeyStorageResult<bool> {
        todo!();
    }
}

impl TryInto<SigningAlgorithmSpec> for JwsAlgorithm {
    type Error = KeyStorageError;

    fn try_into(self) -> Result<SigningAlgorithmSpec, Self::Error> {
        let alg_spec = match self {
            // ECDSA using P-256 and SHA-256
            JwsAlgorithm::ES256 => SigningAlgorithmSpec::EcdsaSha256,
            // ECDSA using P-384 and SHA-384
            JwsAlgorithm::ES384 => SigningAlgorithmSpec::EcdsaSha384,
            // ECDSA using P-521 and SHA-512
            JwsAlgorithm::ES512 => SigningAlgorithmSpec::EcdsaSha512,
            // TODO: which of the two?
            JwsAlgorithm::EdDSA => SigningAlgorithmSpec::Ed25519Sha512,
            // ECDSA using K-256 and SHA-256
            JwsAlgorithm::ES256K => SigningAlgorithmSpec::EcdsaSha256,
            // JwsAlgorithm::EdDSA => SigningAlgorithmSpec::Ed25519PhSha512,
            // This mapping direction should be fine, the reverse seems to be key dependent.
            // Following [aws documentation](https://docs.aws.amazon.com/kms/latest/developerguide/symm-asymm-choose-key-spec.html#key-spec-mldsa),
            // algorithm on AWS side should be the catch-it-all for all key types, but resulting signature length should vary based on
            // used key type as specified in table 2 [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final).
            // TODO: Check if a one sided conversion like this is actually useful or if we have to adjust the conversion.
            JwsAlgorithm::ML_DSA_44 | JwsAlgorithm::ML_DSA_65 | JwsAlgorithm::ML_DSA_87 => {
                SigningAlgorithmSpec::MlDsaShake256
            }
            // RSASSA-PKCS1-v1_5 using SHA-256
            JwsAlgorithm::RS256 => SigningAlgorithmSpec::RsassaPkcs1V15Sha256,
            // RSASSA-PKCS1-v1_5 using SHA-384
            JwsAlgorithm::RS384 => SigningAlgorithmSpec::RsassaPkcs1V15Sha384,
            // RSASSA-PKCS1-v1_5 using SHA-512
            JwsAlgorithm::RS512 => SigningAlgorithmSpec::RsassaPkcs1V15Sha512,
            // RSASSA-PSS using SHA-256 and MGF1 with SHA-256
            JwsAlgorithm::PS256 => SigningAlgorithmSpec::RsassaPssSha256,
            // RSASSA-PSS using SHA-384 and MGF1 with SHA-384
            JwsAlgorithm::PS384 => SigningAlgorithmSpec::RsassaPssSha384,
            // RSASSA-PSS using SHA-512 and MGF1 with SHA-512
            JwsAlgorithm::PS512 => SigningAlgorithmSpec::RsassaPssSha512,
            // SM2DSA currently not part of the [JOSE spec](https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms)
            // therefore omitting it for now
            other => {
                return Err(KeyStorageError::new(
                    KeyStorageErrorKind::UnsupportedSignatureAlgorithm,
                )
                .with_custom_message(format!("unsupported signature algorithm: {}", other)));
            }
        };

        Ok(alg_spec)
    }
}

impl Into<KeyType> for KeySpec {
    fn into(self) -> KeyType {
        KeyType::from_static_str(self.into())
    }
}
