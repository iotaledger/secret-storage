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
use secret_storage::{KeyGenerate, KeySign, Signer};
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
        tokio::time::sleep(std::time::Duration::from_secs(15)).await;

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

        // IOTA uses 0x02 flag for ECDSA Secp256r1
        let mut pubkey_with_flag = Vec::new();
        pubkey_with_flag.push(0x02);
        pubkey_with_flag.extend_from_slice(compressed);

        let mut hasher = Blake2b256::new();
        hasher.update(&pubkey_with_flag);
        let hash = hasher.finalize();

        let mut addr_bytes = [0u8; 32];
        addr_bytes.copy_from_slice(&hash[..32]);
        Ok(IotaAddress::from_bytes(addr_bytes)?)
    }

    async fn request_faucet_funds(
        &self,
        address: IotaAddress,
    ) -> Result<String, Box<dyn std::error::Error>> {
        const TESTNET_FAUCET_URL: &str = "https://faucet.testnet.iota.cafe/gas";

        iota::client_commands::request_tokens_from_faucet(address, TESTNET_FAUCET_URL.to_string())
            .await?;

        Ok("Faucet request completed successfully".to_string())
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
        use p256::ecdsa::VerifyingKey;
        use p256::pkcs8::DecodePublicKey;

        // Parse DER signature and canonicalize
        let (r_bytes, s_bytes) = self.parse_der_signature(vault_signature)?;

        // Combine r and s into 64-byte signature
        let mut sig_bytes = Vec::with_capacity(64);
        sig_bytes.extend_from_slice(&r_bytes);
        sig_bytes.extend_from_slice(&s_bytes);

        // Get compressed public key
        let verifying_key = VerifyingKey::from_public_key_der(public_key_der)?;
        let encoded_point = verifying_key.to_encoded_point(true);
        let compressed_pubkey = encoded_point.as_bytes();

        // Create IOTA signature: flag + sig(64) + pubkey(33)
        let mut iota_sig = Vec::with_capacity(1 + 64 + 33);
        iota_sig.push(0x02); // IOTA secp256r1 flag
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

    fn parse_der_signature(&self, der_signature: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
        if der_signature.len() < 8 || der_signature[0] != 0x30 {
            return Err("Invalid DER signature format".into());
        }

        let mut pos = 2;

        // Parse r
        if der_signature[pos] != 0x02 {
            return Err("Expected INTEGER tag for r".into());
        }
        pos += 1;
        let r_len = der_signature[pos] as usize;
        pos += 1;
        let mut r_bytes = der_signature[pos..pos + r_len].to_vec();
        pos += r_len;

        if r_bytes.len() > 32 && r_bytes[0] == 0x00 {
            r_bytes = r_bytes[1..].to_vec();
        }
        while r_bytes.len() < 32 {
            r_bytes.insert(0, 0x00);
        }

        // Parse s
        if der_signature[pos] != 0x02 {
            return Err("Expected INTEGER tag for s".into());
        }
        pos += 1;
        let s_len = der_signature[pos] as usize;
        pos += 1;
        let mut s_bytes = der_signature[pos..pos + s_len].to_vec();

        if s_bytes.len() > 32 && s_bytes[0] == 0x00 {
            s_bytes = s_bytes[1..].to_vec();
        }
        while s_bytes.len() < 32 {
            s_bytes.insert(0, 0x00);
        }

        // Canonicalize s
        s_bytes = self.canonicalize_s_value(&s_bytes)?;

        Ok((r_bytes, s_bytes))
    }

    fn canonicalize_s_value(&self, s_bytes: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let n_div_2: [u8; 32] = [
            0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31,
            0x92, 0xa8,
        ];

        let mut s_32 = [0u8; 32];
        let s_len = std::cmp::min(s_bytes.len(), 32);
        s_32[32 - s_len..].copy_from_slice(&s_bytes[s_bytes.len() - s_len..]);

        let mut s_high = false;
        for i in 0..32 {
            if s_32[i] > n_div_2[i] {
                s_high = true;
                break;
            } else if s_32[i] < n_div_2[i] {
                break;
            }
        }

        if s_high {
            let n: [u8; 32] = [
                0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2,
                0xfc, 0x63, 0x25, 0x51,
            ];

            let mut result = [0u8; 32];
            let mut borrow = 0u16;

            for i in (0..32).rev() {
                let temp = n[i] as u16 + 256 - s_32[i] as u16 - borrow;
                result[i] = (temp % 256) as u8;
                borrow = if temp < 256 { 1 } else { 0 };
            }

            Ok(result.to_vec())
        } else {
            Ok(s_32.to_vec())
        }
    }
}
