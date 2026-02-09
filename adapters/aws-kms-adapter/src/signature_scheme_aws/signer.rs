use async_trait::async_trait;
use secret_storage::{Result, SignatureScheme, Signer};

use crate::AwsKmsSigner;

use super::AwsKmsSignatureScheme;

type Input = <AwsKmsSignatureScheme as SignatureScheme>::Input;
type PublicKey = <AwsKmsSignatureScheme as SignatureScheme>::PublicKey;
type Signature = <AwsKmsSignatureScheme as SignatureScheme>::Signature;

#[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync-storage", async_trait)]
impl Signer<AwsKmsSignatureScheme> for AwsKmsSigner {
    type KeyId = String;

    async fn sign(&self, data: &Input) -> Result<Signature> {
        self.sign(data).await
    }

    async fn public_key(&self) -> Result<PublicKey> {
        self.public_key().await
    }

    fn key_id(&self) -> Self::KeyId {
        self.key_id()
    }
}
