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
use iota_interaction::OptionalSend;
use iota_interaction::OptionalSync;
use multi_schema::KeyType as MultiSchemaKeyType;
use multi_schema::SignatureSchemeMulti;
use secret_storage::KeyDelete;
use secret_storage::KeyExist;
use secret_storage::KeyGenerate;
use secret_storage::KeySignWithOptions;
use secret_storage::Signer;

use crate::storage::IotaCompatibleKeyStorage;
use crate::utils::convert_public_key_der_to_iota_public_key;

#[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync-storage", async_trait)]
impl<TInner> JwkStorage for IotaCompatibleKeyStorage<TInner>
where
    TInner: KeyGenerate<SignatureSchemeMulti, String, Options: TryFrom<MultiSchemaKeyType>>
        + KeySignWithOptions<SignatureSchemeMulti, String, Options: TryFrom<MultiSchemaKeyType>>
        + KeyDelete<String>
        + KeyExist<String>
        + OptionalSync
        + OptionalSend,
    <TInner as KeySignWithOptions<SignatureSchemeMulti, String>>::Signer: OptionalSend,
{
    async fn generate(
        &self,
        key_type: IdentityStorageKeyType,
        alg: JwsAlgorithm,
    ) -> KeyStorageResult<JwkGenOutput> {
        let key_type = MultiSchemaKeyType::from_str(&key_type.to_string()).unwrap();
        let signature_type_from_alg: MultiSchemaKeyType = alg_to_key_type(&alg)?;
        if key_type != signature_type_from_alg {
            panic!("key type and algorithm mismatch");
        }
        let (kms_key_id, public_key) = self
            .inner
            .generate_key_with_options(
                signature_type_from_alg
                    .try_into()
                    .map_err(|_| KeyStorageError::new(KeyStorageErrorKind::UnsupportedKeyType))?,
            )
            .await
            .unwrap();

        let public_key_iota =
            convert_public_key_der_to_iota_public_key(&public_key.bytes, &public_key.key_type)
                .unwrap();

        let mut jwk = ToJwk::to_jwk(&public_key_iota).unwrap();
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

        let key_type: MultiSchemaKeyType = alg_to_key_type(&alg)?;

        let inner_signer = self
            .inner
            .get_signer_with_options(
                &key_id.to_string(),
                &key_type
                    .try_into()
                    .map_err(|_| KeyStorageError::new(KeyStorageErrorKind::UnsupportedKeyType))?,
            )
            .unwrap();

        let signature = inner_signer.sign(&data.to_vec()).await.unwrap();

        Ok(signature.bytes)
    }

    async fn delete(&self, key_id: &KeyId) -> KeyStorageResult<()> {
        Ok(self.inner.delete(&key_id.to_string()).await.unwrap())
    }

    async fn exists(&self, key_id: &KeyId) -> KeyStorageResult<bool> {
        Ok(self.inner.exist(&key_id.to_string()).await.unwrap())
    }
}

fn alg_to_key_type(alg: &JwsAlgorithm) -> KeyStorageResult<MultiSchemaKeyType> {
    let key_type = match alg {
        JwsAlgorithm::ES256 => MultiSchemaKeyType::P256DerEncoded,
        JwsAlgorithm::ES256K => MultiSchemaKeyType::K256DerEncoded,
        JwsAlgorithm::EdDSA => MultiSchemaKeyType::Ed25519DerEncoded,
        other => {
            return Err(
                KeyStorageError::new(KeyStorageErrorKind::UnsupportedKeyType)
                    .with_custom_message(format!("{other} not supported")),
            );
        }
    };

    Ok(key_type)
}
