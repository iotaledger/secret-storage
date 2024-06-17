use fastcrypto::hash::{Blake2b256, HashFunction};
use serde::Serialize;
use shared_crypto::intent::{Intent, IntentMessage};

pub trait ToHash {
    fn calculate_data_hash(&self) -> [u8; 32];
}

impl<D> ToHash for D
where
    D: Serialize,
{
    fn calculate_data_hash(&self) -> [u8; 32] {
        let msg = IntentMessage::new(Intent::sui_transaction(), self);
        let mut hasher = Blake2b256::default();
        hasher.update(&bcs::to_bytes(&msg).expect("Message serialization should not fail"));
        hasher.finalize().digest
    }
}
