use iota_types::transaction::TransactionData;

use crate::{hash::ToHash, key_signature_set::KeySignatureSet, prelude::Signer};

/// Transaction signer trait is a trait is a helper auto-trait that allows to sign IOTA Transactions
/// This trait requires to `transaction_helper` feature to be enabled.
/// Because the `TransactionData` is domain specific, the `transaction_helper` feature is disabled by default.
pub trait TransactionSigner<K: KeySignatureSet>: Signer<K> {
    async fn sign_transaction(
        &self,
        transaction: &TransactionData,
    ) -> Result<K::Signature, anyhow::Error> {
        let hash = transaction.calculate_data_hash();
        self.sign(hash).await
    }
}
