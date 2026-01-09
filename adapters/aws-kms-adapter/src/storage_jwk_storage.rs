use std::collections::HashMap;
use std::error::Error;
use std::fmt::Display;
use std::str::FromStr;

use async_trait::async_trait;
use aws_sdk_kms::types::SigningAlgorithmSpec;
use identity_iota::storage::JwkGenOutput;
use identity_iota::storage::JwkStorage;
use identity_iota::storage::KeyId;
use identity_iota::storage::KeyStorageError;
use identity_iota::storage::KeyStorageErrorKind;
use identity_iota::storage::KeyStorageResult;
use identity_iota::storage::KeyType;
use identity_iota::verification::jwk;
use identity_iota::verification::jwk::EdCurve;
use identity_iota::verification::jwk::Jwk;
use identity_iota::verification::jwk::JwkParamsEc;
use identity_iota::verification::jwk::JwkParamsOkp;
use identity_iota::verification::jwk::ToJwk;
use identity_iota::verification::jws::JwsAlgorithm;
use identity_iota::verification::jwu::encode_b64;
use iota_interaction::types::crypto::PublicKey;
use iota_interaction::IotaKeySignature;
use k256::ecdsa::Signature as K256Signature;
use p256::ecdsa::Signature as P256Signature;
use p256::PublicKey as P256PublicKey;
use secret_storage::KeyGenerate;
use secret_storage::KeyGet;
use secret_storage::KeySign;
use tokio::sync::RwLockReadGuard;
use tokio::sync::RwLockWriteGuard;

use crate::convert_public_key_der_to_iota_public_key;
use crate::sign;
use crate::AwsKmsKeyOptions;
use crate::AwsKmsSignatureScheme;
use crate::AwsKmsSigner;
use crate::AwsKmsStorage;
use crate::KeySpec;

fn create_jwk_for_public_key(iota_public_key: &PublicKey) -> Jwk {
    let mut jwk = ToJwk::to_jwk(iota_public_key).unwrap();
    jwk.set_kid(jwk.thumbprint_sha256_b64());

    jwk
}

fn key_alg_mismatch_error(key_spec: &KeySpec, alg: &JwsAlgorithm) -> KeyStorageError {
    KeyStorageError::new(KeyStorageErrorKind::KeyAlgorithmMismatch).with_custom_message(format!(
        "`cannot use key type `{}` with algorithm `{}`",
        key_spec.to_aws_key_spec(),
        alg
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
        alias: None, // Closest thing to an alias we could use, would be the `kid`, but this is derived afterwards
        tags: vec![
            (
                "CreatedBy".to_string(),
                "aws_kms_adapter::storage::AwsKmsStorage".to_string(),
            ),
            (
                "identity_storage::key_storage::KeyType".to_string(),
                key_type.to_string(),
            ),
            (
                "identity_jose::jws::algorithm::JwsAlgorithm".to_string(),
                alg.to_string(),
            ),
        ],
        key_spec: Some(key_spec.clone()),
    }
}

/// Check that the key type can be used with the algorithm.
fn check_key_alg_compatibility(key_spec: &KeySpec, alg: &JwsAlgorithm) -> KeyStorageResult<()> {
    match (key_spec, &alg) {
        (KeySpec::EccNistP256, JwsAlgorithm::ES256) => Ok(()),
        (KeySpec::EccSecgP256k1, JwsAlgorithm::ES256K) => Ok(()),
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
        // validate key/alg syntax and parse them
        let key_spec = KeySpec::try_from(key_type.as_str()).map_err(|err| {
            KeyStorageError::new(KeyStorageErrorKind::UnsupportedKeyType).with_source(err)
        })?;
        // TODO: resulting `SigningAlgorithmSpec` should be used as tag in `aws_kms_key_options` to keep values AWS specific
        // check alg value validity
        let _alg_spec = to_signing_algorithm_spec(&alg)?;

        check_key_alg_compatibility(&key_spec, &alg)?;

        let (aws_key_id, public_key) =
            KeyGenerate::<IotaKeySignature, String>::generate_key_with_options(
                self,
                aws_kms_key_options(&key_spec, &key_type, &alg),
            )
            .await
            .map_err(|err| {
                KeyStorageError::new(KeyStorageErrorKind::RetryableIOFailure).with_custom_message(
                    format!("failed to generate key in AWS; {}", &err.to_string()),
                )
            })?;
        let jwk = create_jwk_for_public_key(&public_key);

        Ok(JwkGenOutput::new(KeyId::new(aws_key_id), jwk))
    }

    // https://docs.aws.amazon.com/kms/latest/developerguide/importing-keys.html
    async fn insert(&self, _jwk: Jwk) -> KeyStorageResult<KeyId> {
        todo!();
        // let key_type = AwsStoreKeyType::try_from(&jwk)?;

        // if !jwk.is_private() {
        //     return Err(KeyStorageError::new(KeyStorageErrorKind::Unspecified)
        //         .with_custom_message("expected a Jwk with all private key components set"));
        // }

        // match jwk.alg() {
        //     Some(alg) => {
        //         let alg: JwsAlgorithm = JwsAlgorithm::from_str(alg).map_err(|err| {
        //             KeyStorageError::new(KeyStorageErrorKind::UnsupportedSignatureAlgorithm)
        //                 .with_source(err)
        //         })?;
        //         check_key_alg_compatibility(key_type, &alg)?;
        //     }
        //     None => {
        //         return Err(KeyStorageError::new(
        //             KeyStorageErrorKind::UnsupportedSignatureAlgorithm,
        //         )
        //         .with_custom_message("expected a Jwk with an `alg` parameter"));
        //     }
        // }

        // if jwk.alg().is_none() {
        //     return Err(
        //         KeyStorageError::new(KeyStorageErrorKind::UnsupportedSignatureAlgorithm)
        //             .with_custom_message("expected a Jwk with an `alg` parameter"),
        //     );
        // }

        // let key_id: KeyId = random_key_id();

        // let mut jwk_store: RwLockWriteGuard<'_, JwkKeyStore> = self.jwk_store.write().await;

        // jwk_store.insert(key_id.clone(), jwk);

        // Ok(key_id)
    }

    async fn sign(
        &self,
        key_id: &KeyId,
        data: &[u8],
        public_key: &Jwk,
    ) -> KeyStorageResult<Vec<u8>> {
        let key_id_string = key_id.to_string();
        let _signer = <AwsKmsStorage as KeySign<AwsKmsSignatureScheme, String>>::get_signer(
            self,
            &key_id_string,
        )
        .map_err(|err| {
            KeyStorageError::new(KeyStorageErrorKind::Unspecified)
                .with_source(err)
                .with_custom_message(format!("failed to create signer"))
        })?;

        // let jwk_store: RwLockReadGuard<'_, JwkKeyStore> = self.jwk_store.read().await;

        // Extract the required alg from the given public key
        let alg = public_key
            .alg()
            .ok_or(KeyStorageErrorKind::UnsupportedSignatureAlgorithm)
            .and_then(|alg_str| {
                JwsAlgorithm::from_str(alg_str)
                    .map_err(|_| KeyStorageErrorKind::UnsupportedSignatureAlgorithm)
            })?;

        // // Check that `kty` is `Okp` and `crv = Ed25519`.
        // match alg {
        //     JwsAlgorithm::EdDSA => {
        //         let okp_params = public_key.try_okp_params().map_err(|err| {
        //             KeyStorageError::new(KeyStorageErrorKind::Unspecified)
        //                 .with_custom_message(format!(
        //                     "expected a Jwk with Okp params in order to sign with {alg}"
        //                 ))
        //                 .with_source(err)
        //         })?;
        //         if okp_params.crv != EdCurve::Ed25519.name() {
        //             return Err(KeyStorageError::new(KeyStorageErrorKind::Unspecified)
        //                 .with_custom_message(format!(
        //                     "expected Jwk with Okp {} crv in order to sign with {alg}",
        //                     EdCurve::Ed25519
        //                 )));
        //         }
        //     }
        //     other => {
        //         return Err(KeyStorageError::new(
        //             KeyStorageErrorKind::UnsupportedSignatureAlgorithm,
        //         )
        //         .with_custom_message(format!("{other} is not supported")));
        //     }
        // };

        let alg_spec = to_signing_algorithm_spec(&alg)?;
        let signature = sign(&self.client, &key_id.to_string(), &data.to_vec(), &alg_spec)
            .await
            .unwrap();

        let signature = match alg {
            JwsAlgorithm::ES256 => P256Signature::from_der(&signature).unwrap().to_vec(),
            JwsAlgorithm::ES256K => K256Signature::from_der(&signature).unwrap().to_vec(),
            // special case for JwsAlgorithm::EdDSA?
            _ => signature,
        };

        Ok(signature)
    }

    async fn delete(&self, _key_id: &KeyId) -> KeyStorageResult<()> {
        dbg!("not deleting key in current test setup");
        Ok(())
        // let mut jwk_store: RwLockWriteGuard<'_, JwkKeyStore> = self.jwk_store.write().await;

        // jwk_store
        //     .remove(key_id)
        //     .map(|_| ())
        //     .ok_or_else(|| KeyStorageError::new(KeyStorageErrorKind::KeyNotFound))
    }

    async fn exists(&self, _key_id: &KeyId) -> KeyStorageResult<bool> {
        todo!();
        // let jwk_store: RwLockReadGuard<'_, JwkKeyStore> = self.jwk_store.read().await;
        // Ok(jwk_store.contains_key(key_id))
    }
}

// /// Try to parse key spec from input. Format is adapter specific and documented
// /// [here](https://docs.aws.amazon.com/kms/latest/developerguide/symm-asymm-choose-key-spec.html).
// fn to_key_spec(key_type: KeyType) -> KeyStorageResult<KeySpec> {
//     let key_spec = KeySpec::try_from(key_type.as_str()).unwrap();
//     Ok(key_spec)
// }

fn to_signing_algorithm_spec(alg: &JwsAlgorithm) -> KeyStorageResult<SigningAlgorithmSpec> {
    let alg_spec = match alg {
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
            return Err(
                KeyStorageError::new(KeyStorageErrorKind::UnsupportedSignatureAlgorithm)
                    .with_custom_message(format!("unsupported signature algorithm: {}", other)),
            );
        }
    };

    Ok(alg_spec)
}

// #[derive(Debug, Copy, Clone)]
// enum AwsStoreKeyType {
//     Ed25519,
//     BLS12381G2,
// }

// impl AwsKmsStorage {
//     const ED25519_KEY_TYPE_STR: &'static str = "Ed25519";
//     /// The Ed25519 key type.
//     pub const ED25519_KEY_TYPE: KeyType = KeyType::from_static_str(Self::ED25519_KEY_TYPE_STR);

//     const BLS12381G2_KEY_TYPE_STR: &'static str = "BLS12381G2";
//     /// The BLS12381G2 key type
//     pub const BLS12381G2_KEY_TYPE: KeyType =
//         KeyType::from_static_str(Self::BLS12381G2_KEY_TYPE_STR);

//     const PQ_KEY_TYPE_STR: &'static str = "AKP";
//     /// ML-DSA algorithms key types;
//     pub const PQ_KEY_TYPE: KeyType = KeyType::from_static_str(Self::PQ_KEY_TYPE_STR);
// }

// impl AwsStoreKeyType {
//     const fn name(&self) -> &'static str {
//         match self {
//             AwsStoreKeyType::Ed25519 => AwsKmsStorage::ED25519_KEY_TYPE_STR,
//             AwsStoreKeyType::BLS12381G2 => AwsKmsStorage::BLS12381G2_KEY_TYPE_STR,
//         }
//     }
// }

// impl Display for AwsStoreKeyType {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         f.write_str(self.name())
//     }
// }

// impl TryFrom<&KeyType> for AwsStoreKeyType {
//     type Error = KeyStorageError;

//     fn try_from(value: &KeyType) -> Result<Self, Self::Error> {
//         match value.as_str() {
//             AwsKmsStorage::ED25519_KEY_TYPE_STR => Ok(AwsStoreKeyType::Ed25519),
//             AwsKmsStorage::BLS12381G2_KEY_TYPE_STR => Ok(AwsStoreKeyType::BLS12381G2),
//             _ => Err(KeyStorageError::new(
//                 KeyStorageErrorKind::UnsupportedKeyType,
//             )),
//         }
//     }
// }

// impl TryFrom<&Jwk> for AwsStoreKeyType {
//     type Error = KeyStorageError;

//     fn try_from(jwk: &Jwk) -> Result<Self, Self::Error> {
//         match jwk.kty() {
//             JwkType::Okp => {
//                 let okp_params = jwk.try_okp_params().map_err(|err| {
//                     KeyStorageError::new(KeyStorageErrorKind::UnsupportedKeyType)
//                         .with_custom_message("expected Okp parameters for a JWK with `kty` Okp")
//                         .with_source(err)
//                 })?;
//                 match okp_params.try_ed_curve().map_err(|err| {
//                     KeyStorageError::new(KeyStorageErrorKind::UnsupportedKeyType)
//                         .with_custom_message("only Ed curves are supported for signing")
//                         .with_source(err)
//                 })? {
//                     EdCurve::Ed25519 => Ok(AwsStoreKeyType::Ed25519),
//                     curve => Err(
//                         KeyStorageError::new(KeyStorageErrorKind::UnsupportedKeyType)
//                             .with_custom_message(format!("{curve} not supported")),
//                     ),
//                 }
//             }
//             JwkType::Ec => {
//                 let ec_params = jwk.try_ec_params().map_err(|err| {
//                     KeyStorageError::new(KeyStorageErrorKind::UnsupportedKeyType)
//                         .with_custom_message("expected EC parameters for a JWK with `kty` Ec")
//                         .with_source(err)
//                 })?;
//                 match ec_params.try_bls_curve().map_err(|err| {
//                     KeyStorageError::new(KeyStorageErrorKind::UnsupportedKeyType)
//                         .with_custom_message("only Ed curves are supported for signing")
//                         .with_source(err)
//                 })? {
//                     BlsCurve::BLS12381G2 => Ok(AwsStoreKeyType::BLS12381G2),
//                     curve => Err(
//                         KeyStorageError::new(KeyStorageErrorKind::UnsupportedKeyType)
//                             .with_custom_message(format!("{curve} not supported")),
//                     ),
//                 }
//             }
//             other => Err(
//                 KeyStorageError::new(KeyStorageErrorKind::UnsupportedKeyType)
//                     .with_custom_message(format!("Jwk `kty` {other} not supported")),
//             ),
//         }
//     }
// }
