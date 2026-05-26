use std::str::FromStr;

use async_trait::async_trait;
use identity_iota::storage::JwkGenOutput;
use identity_iota::storage::JwkStorage;
use identity_iota::storage::KeyId;
use identity_iota::storage::KeyStorageError;
use identity_iota::storage::KeyStorageErrorKind;
use identity_iota::storage::KeyStorageResult;
use identity_iota::storage::KeyType as IdentityStorageKeyType;
use identity_iota::verification::jwk::Jwk;
use identity_iota::verification::jwk::ToJwk;
use identity_iota::verification::jws::JwsAlgorithm;
use iota_interaction::IotaKeySignature;
use iota_interaction::OptionalSend;
use iota_interaction::OptionalSync;
use typed_key_signature::KeyIdDefinition;
use typed_key_signature::KeyType as TypedKeySignatureKeyType;
use typed_key_signature::TypedKeySignature;
use secret_storage::KeyDelete;
use secret_storage::KeyExist;
use secret_storage::KeyGenerate;
use secret_storage::KeyGet;
use secret_storage::KeySignWithOptions;
use secret_storage::Signer;

use crate::storage::IotaCompatibleKeyStorage;
use crate::utils::convert_public_key_der_to_iota_public_key;

#[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync-storage", async_trait)]
impl<TInner> JwkStorage for IotaCompatibleKeyStorage<TInner>
where
    TInner: KeyGenerate<TypedKeySignature, String, Options: TryFrom<TypedKeySignatureKeyType>>
        + KeySignWithOptions<TypedKeySignature, String, Options: TryFrom<TypedKeySignatureKeyType>>
        + KeyDelete<String>
        + KeyExist<String>
        + OptionalSync
        + OptionalSend,
    <TInner as KeySignWithOptions<TypedKeySignature, String>>::Signer: OptionalSend,
{
    async fn generate(
        &self,
        key_type: IdentityStorageKeyType,
        alg: JwsAlgorithm,
    ) -> KeyStorageResult<JwkGenOutput> {
        let key_type = identity_key_type_to_typed_key_signature(&key_type)?;
        let signature_type_from_alg: TypedKeySignatureKeyType = alg_to_key_type(&alg)?;
        if key_type != signature_type_from_alg {
            return Err(
                KeyStorageError::new(KeyStorageErrorKind::UnsupportedKeyType).with_custom_message(
                    format!("key type \"{key_type}\" does not match algorithm \"{alg}\""),
                ),
            );
        }
        let (kms_key_id, public_key) = self
            .inner
            .generate_key_with_options(
                signature_type_from_alg
                    .try_into()
                    .map_err(|_| KeyStorageError::new(KeyStorageErrorKind::UnsupportedKeyType))?,
            )
            .await
            .map_err(|e| {
                KeyStorageError::new(KeyStorageErrorKind::Unspecified)
                    .with_custom_message(e.to_string())
            })?;

        let public_key_iota =
            convert_public_key_der_to_iota_public_key(&public_key.bytes(), &public_key.key_type())
                .map_err(|e| {
                    KeyStorageError::new(KeyStorageErrorKind::Unspecified)
                        .with_custom_message(e.to_string())
                })?;

        let mut jwk = ToJwk::to_jwk(&public_key_iota).map_err(|e| {
            KeyStorageError::new(KeyStorageErrorKind::Unspecified).with_custom_message(e.to_string())
        })?;
        jwk.set_kid(jwk.thumbprint_sha256_b64());

        Ok(JwkGenOutput::new(KeyId::new(kms_key_id), jwk))
    }

    async fn insert(&self, _jwk: Jwk) -> KeyStorageResult<KeyId> {
        Err(
            KeyStorageError::new(KeyStorageErrorKind::Unspecified).with_custom_message(
                "Insert operation not supported for generic JwkStorage implementation.",
            ),
        )
    }

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

        let key_type: TypedKeySignatureKeyType = alg_to_key_type(&alg)?;

        let inner_signer = self
            .inner
            .get_signer_with_options(
                &key_id.to_string(),
                &key_type
                    .try_into()
                    .map_err(|_| KeyStorageError::new(KeyStorageErrorKind::UnsupportedKeyType))?,
            )
            .map_err(|e| {
                KeyStorageError::new(KeyStorageErrorKind::Unspecified)
                    .with_custom_message(e.to_string())
            })?;

        let signature = inner_signer
            .sign(&data.to_vec())
            .await
            .map_err(|e| {
                KeyStorageError::new(KeyStorageErrorKind::Unspecified)
                    .with_custom_message(e.to_string())
            })?;

        Ok(signature.bytes().clone())
    }

    async fn delete(&self, key_id: &KeyId) -> KeyStorageResult<()> {
        self.inner.delete(&key_id.to_string()).await.map_err(|e| {
            KeyStorageError::new(KeyStorageErrorKind::Unspecified).with_custom_message(e.to_string())
        })
    }

    async fn exists(&self, key_id: &KeyId) -> KeyStorageResult<bool> {
        self.inner.exist(&key_id.to_string()).await.map_err(|e| {
            KeyStorageError::new(KeyStorageErrorKind::Unspecified).with_custom_message(e.to_string())
        })
    }
}

impl<TInner> IotaCompatibleKeyStorage<TInner>
where
    TInner: KeyGet<TypedKeySignature, TInner::KeyId> + KeyIdDefinition + OptionalSync,
{
    pub async fn public_key_jwk(&self, key_id: &str) -> KeyStorageResult<Jwk> {
        let public_key = <Self as KeyGet<IotaKeySignature, String>>::public_key(self, &key_id.to_owned())
            .await
            .map_err(|e| {
                KeyStorageError::new(KeyStorageErrorKind::Unspecified)
                    .with_custom_message(e.to_string())
            })?;
        let mut jwk = ToJwk::to_jwk(&public_key).map_err(|e| {
            KeyStorageError::new(KeyStorageErrorKind::Unspecified)
                .with_custom_message(e.to_string())
        })?;
        jwk.set_kid(jwk.thumbprint_sha256_b64());
        Ok(jwk)
    }
}

fn identity_key_type_to_typed_key_signature(
    key_type: &IdentityStorageKeyType,
) -> KeyStorageResult<TypedKeySignatureKeyType> {
    match key_type.as_str() {
        "Ed25519" => Ok(TypedKeySignatureKeyType::Ed25519DerEncoded),
        "secp256r1" => Ok(TypedKeySignatureKeyType::Secp256r1DerEncoded),
        "secp256k1" => Ok(TypedKeySignatureKeyType::Secp256k1DerEncoded),
        other => Err(
            KeyStorageError::new(KeyStorageErrorKind::UnsupportedKeyType)
                .with_custom_message(format!("key type \"{}\" is not supported", other)),
        ),
    }
}

fn alg_to_key_type(alg: &JwsAlgorithm) -> KeyStorageResult<TypedKeySignatureKeyType> {
    let key_type = match alg {
        JwsAlgorithm::ES256 => TypedKeySignatureKeyType::Secp256r1DerEncoded,
        JwsAlgorithm::ES256K => TypedKeySignatureKeyType::Secp256k1DerEncoded,
        JwsAlgorithm::EdDSA => TypedKeySignatureKeyType::Ed25519DerEncoded,
        other => {
            return Err(
                KeyStorageError::new(KeyStorageErrorKind::UnsupportedKeyType)
                    .with_custom_message(format!("{other} not supported")),
            );
        }
    };

    Ok(key_type)
}
