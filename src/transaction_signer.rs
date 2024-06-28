use iota_types::crypto::Signature as IotaSignature;
use iota_types::transaction::TransactionData;

use crate::{hash::GetHash, key_signature_set::KeySignatureTypes, prelude::Signer};
use async_trait::async_trait;

/// Transaction signer trait is a trait is a helper auto-trait that allows to sign IOTA Transactions
/// This trait requires to `transaction_helper` feature to be enabled.
/// Because the `TransactionData` and `Signature` are domain specific, the `transaction_helper` feature
/// is disabled by default.
#[async_trait]
pub trait TransactionSigner<K: KeySignatureTypes>: Send + Sync {
    async fn sign_transaction(
        &self,
        transaction: &TransactionData,
    ) -> Result<IotaSignature, anyhow::Error>;
}

#[async_trait]
impl<K, T> TransactionSigner<K> for T
where
    K: KeySignatureTypes,
    K::Signature: Into<IotaSignature>,
    T: Signer<K>,
{
    async fn sign_transaction(
        &self,
        transaction: &TransactionData,
    ) -> Result<IotaSignature, anyhow::Error> {
        let hash = transaction.get_hash();
        self.sign(&hash).await.map(Into::into)
    }
}
