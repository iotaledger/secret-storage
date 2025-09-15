// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Faucet utilities for IOTA testnet

use anyhow::Context;
use iota_types::base_types::IotaAddress;
use std::error::Error;

const TESTNET_FAUCET_URL: &str = "https://faucet.testnet.iota.cafe/gas";

/// Request funds from IOTA testnet faucet
pub async fn request_faucet_funds(address: IotaAddress) -> Result<String, Box<dyn Error>> {
    // Use IOTA's official faucet client command
    iota::client_commands::request_tokens_from_faucet(address, TESTNET_FAUCET_URL.to_string())
        .await
        .context("Failed to request tokens from faucet")?;

    Ok("Faucet request completed successfully".to_string())
}
