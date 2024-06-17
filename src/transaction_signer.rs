use sui_types::transaction::TransactionData;

use crate::{hash::ToHash, key_signature_set::KeySignatureSet, prelude::Signer};

pub trait TransactionSigner<K: KeySignatureSet>: Signer<K> {
    async fn sign_transaction(
        &self,
        transaction: &TransactionData,
    ) -> Result<K::Signature, anyhow::Error> {
        let hash = transaction.calculate_data_hash();
        self.sign(hash).await
    }
}
