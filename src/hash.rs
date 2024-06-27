use fastcrypto::hash::{Blake2b256, HashFunction};
use iota_types::transaction::TransactionData;
use shared_crypto::intent::{Intent, IntentMessage};

/// ToHash trait is a helper trait that allows to calculate the hash of the data.
/// The calculation of hash is domain (IOTA) specific, therefore this trait is not included with default features.
pub trait GetHash {
    fn get_hash(&self) -> [u8; 32];
}

impl GetHash for TransactionData {
    fn get_hash(&self) -> [u8; 32] {
        let msg = IntentMessage::new(Intent::sui_transaction(), self);
        let mut hasher = Blake2b256::default();
        hasher.update(&bcs::to_bytes(&msg).expect("Message serialization should not fail"));
        hasher.finalize().digest
    }
}