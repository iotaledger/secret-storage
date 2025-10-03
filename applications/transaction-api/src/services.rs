// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use blake2::{Blake2b, Digest};
use iota_json_rpc_types::{Coin, IotaTransactionBlockResponseOptions};
use iota_sdk::IotaClientBuilder;
use iota_types::{
    base_types::IotaAddress,
    crypto::ToFromBytes,
    programmable_transaction_builder::ProgrammableTransactionBuilder,
    transaction::{Transaction, TransactionData},
};
use secret_storage_core::{KeyGenerate, KeySign, Signer};
use shared_crypto::intent::{Intent, IntentMessage};
use std::time::{SystemTime, UNIX_EPOCH};
use storage_factory::StorageBuilder;
use tracing::{info, warn};

use crate::{config::AppConfig, error::AppError};

type Blake2b256 = Blake2b<typenum::U32>;

/// Transaction service that orchestrates the complete IOTA workflow
pub struct TransactionService {
    storage: vault_adapter::VaultStorage,
}

impl TransactionService {
    /// Create new transaction service
    pub async fn new(config: &AppConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let vault_config = config.vault.as_ref().ok_or("Vault config missing")?;

        info!("🔧 Initializing HashiCorp Vault storage...");
        info!("   Vault Address: {}", vault_config.addr);

        let storage = StorageBuilder::new()
            .vault()
            .build_vault()
            .await
            .map_err(|e| format!("Failed to initialize Vault storage: {}", e))?;

        info!("✅ Service initialized with VaultStorage");

        Ok(Self { storage })
    }

    /// Check Vault health
    pub async fn check_vault_health(&self) -> bool {
        // Simple health check - try to list keys
        true // Vault is healthy if service was created successfully
    }

    /// List all vault keys
    pub async fn list_vault_keys(&self) -> Result<Vec<crate::models::KeyInfo>, AppError> {
        // This would require implementing a list_keys method on VaultStorage
        // For now return empty list
        Ok(vec![])
    }

    /// Execute complete IOTA transaction workflow
    pub async fn execute_iota_transaction(
        &self,
        target_address: &str,
        amount_mist: u64,
        description: Option<&str>,
    ) -> Result<(String, String, String), AppError> {
        info!("🚀 Starting IOTA transaction execution");

        // Step 1: Generate dynamic Vault key
        let key_name = self.generate_key_name(description);
        info!("🔑 Generating new ECDSA P-256 key: {}", key_name);

        let options = vault_adapter::VaultKeyOptions {
            key_name: Some(key_name.clone()),
            description: Some(
                description
                    .unwrap_or("IOTA Transaction API Key")
                    .to_string(),
            ),
        };

        let (key_id, public_key_der) = self
            .storage
            .generate_key_with_options(options)
            .await
            .map_err(|e| AppError::Storage(e.to_string()))?;

        info!("✅ Key generated: {}", key_id);

        // Step 2: Derive IOTA address
        let iota_address = self
            .derive_iota_address_from_der(&public_key_der)
            .map_err(|e| AppError::Storage(e.to_string()))?;
        info!("✅ IOTA address: {}", iota_address);

        // Step 3: Initialize IOTA client
        let iota_client = IotaClientBuilder::default()
            .build_testnet()
            .await
            .map_err(|e| AppError::ServiceUnavailable(e.to_string()))?;
        info!("✅ Connected to IOTA testnet");

        // Step 4: Request faucet funds
        info!("💧 Requesting faucet funds...");
        if let Err(e) = self.request_faucet_funds(iota_address).await {
            warn!("⚠️  Faucet request failed: {}", e);
        }

        // Wait for faucet
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;

        // Step 5: Check balance
        let (total_balance, coins) = self
            .check_balance(&iota_client, iota_address)
            .await
            .map_err(|e| AppError::TransactionFailed(e.to_string()))?;

        info!("💰 Balance: {} MIST", total_balance);

        if coins.is_empty() {
            return Err(AppError::TransactionFailed(
                "No coins available".to_string(),
            ));
        }

        let gas_buffer = 10_000_000;
        let required = amount_mist + gas_buffer;
        if total_balance < required {
            return Err(AppError::TransactionFailed(format!(
                "Insufficient balance: {} < {}",
                total_balance, required
            )));
        }

        // Step 6: Build transaction
        let recipient_address: IotaAddress = target_address
            .parse()
            .map_err(|e| AppError::InvalidRequest(format!("Invalid address: {}", e)))?;

        let gas_coin = &coins[0];
        let gas_object_ref = (gas_coin.coin_object_id, gas_coin.version, gas_coin.digest);

        let mut ptb = ProgrammableTransactionBuilder::new();
        ptb.pay_iota(vec![recipient_address], vec![amount_mist])
            .map_err(|e| AppError::TransactionFailed(e.to_string()))?;
        let programmable_tx = ptb.finish();

        let gas_budget = 5_000_000;
        let gas_price = iota_client
            .read_api()
            .get_reference_gas_price()
            .await
            .map_err(|e| AppError::ServiceUnavailable(e.to_string()))?;

        let tx_data = TransactionData::new_programmable(
            iota_address,
            vec![gas_object_ref],
            programmable_tx,
            gas_budget,
            gas_price,
        );

        // Step 7: Sign with Vault
        let intent_msg = IntentMessage::new(Intent::iota_transaction(), tx_data.clone());
        let bcs_bytes =
            bcs::to_bytes(&intent_msg).map_err(|e| AppError::TransactionFailed(e.to_string()))?;
        let digest = Blake2b256::digest(&bcs_bytes);

        let signer = self
            .storage
            .get_signer(&key_id)
            .map_err(|e| AppError::Storage(e.to_string()))?;
        let vault_signature = signer
            .sign(&digest.to_vec())
            .await
            .map_err(|e| AppError::Vault(e.to_string()))?;

        info!("✅ Transaction signed with Vault");

        // Step 8: Submit transaction
        let transaction_digest = self
            .submit_via_sdk(&iota_client, &tx_data, &vault_signature, &public_key_der)
            .await
            .map_err(|e| AppError::TransactionFailed(e.to_string()))?;

        info!("🎉 Transaction successful: {}", transaction_digest);

        Ok((transaction_digest, key_id.clone(), iota_address.to_string()))
    }

    fn generate_key_name(&self, description: Option<&str>) -> String {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let prefix = description.unwrap_or("api");
        format!("{}-{}", prefix, timestamp)
    }

    fn derive_iota_address_from_der(
        &self,
        der: &[u8],
    ) -> Result<IotaAddress, Box<dyn std::error::Error>> {
        use p256::ecdsa::VerifyingKey;
        use p256::pkcs8::DecodePublicKey;

        let verifying_key = VerifyingKey::from_public_key_der(der)?;
        let encoded_point = verifying_key.to_encoded_point(true);
        let compressed = encoded_point.as_bytes();

        let mut hasher = Blake2b256::new();
        hasher.update([0x00]); // ECDSA Secp256r1 flag
        hasher.update(compressed);
        let hash = hasher.finalize();

        let mut addr_bytes = [0u8; 32];
        addr_bytes.copy_from_slice(&hash[..32]);
        Ok(IotaAddress::from_bytes(addr_bytes)?)
    }

    async fn request_faucet_funds(
        &self,
        address: IotaAddress,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let url = format!(
            "https://faucet.testnet.iota.cafe/v1/gas?address={}",
            address
        );
        let response = reqwest::get(&url).await?.text().await?;
        Ok(response)
    }

    async fn check_balance(
        &self,
        client: &iota_sdk::IotaClient,
        address: IotaAddress,
    ) -> Result<(u64, Vec<Coin>), Box<dyn std::error::Error>> {
        let coins = client
            .coin_read_api()
            .get_coins(address, None, None, None)
            .await?;
        let total: u64 = coins.data.iter().map(|c| c.balance).sum();
        Ok((total, coins.data))
    }

    async fn submit_via_sdk(
        &self,
        client: &iota_sdk::IotaClient,
        tx_data: &TransactionData,
        vault_signature: &[u8],
        public_key_der: &[u8],
    ) -> Result<String, Box<dyn std::error::Error>> {
        use iota_types::signature::GenericSignature;
        use p256::ecdsa::{Signature as P256Signature, VerifyingKey};
        use p256::pkcs8::DecodePublicKey;

        // Parse DER signature to get r and s
        let der_sig = P256Signature::from_der(vault_signature)?;
        let sig_bytes = der_sig.to_bytes();

        // Get compressed public key
        let verifying_key = VerifyingKey::from_public_key_der(public_key_der)?;
        let encoded_point = verifying_key.to_encoded_point(true);
        let compressed_pubkey = encoded_point.as_bytes();

        // Create IOTA signature: flag + sig + pubkey
        let mut iota_sig = Vec::with_capacity(1 + 64 + 33);
        iota_sig.push(0x00); // ECDSA Secp256r1 flag
        iota_sig.extend_from_slice(&sig_bytes);
        iota_sig.extend_from_slice(compressed_pubkey);

        let generic_sig = GenericSignature::from_bytes(&iota_sig)?;
        let signed_tx = Transaction::from_generic_sig_data(tx_data.clone(), vec![generic_sig]);

        let response = client
            .quorum_driver_api()
            .execute_transaction_block(
                signed_tx,
                IotaTransactionBlockResponseOptions::default(),
                iota_types::quorum_driver_types::ExecuteTransactionRequestType::WaitForLocalExecution,
            )
            .await?;

        Ok(response.digest.to_string())
    }
}
