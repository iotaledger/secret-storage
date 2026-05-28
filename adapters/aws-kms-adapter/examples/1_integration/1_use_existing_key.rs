// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use examples::key_config_from_existing_key_id;
use examples::run_example_for_key_config;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let key_id = std::env::var("AWS_KEY_ID")
        .map_err(|_| anyhow::anyhow!("AWS_KEY_ID must be set to an existing AWS KMS key ID"))?;
    println!("AWS_KEY_ID={key_id}");

    let key_config = key_config_from_existing_key_id(key_id).await?;
    run_example_for_key_config(&key_config).await?;

    Ok(())
}
