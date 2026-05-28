// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// Two keys are created per run: one tx signing key and one JWK signing key.
// The JWK signing key is scheduled for deletion automatically. The tx signing key is kept —
// its ID is printed for use in 1_use_existing_key.rs.

use examples::key_config_from_env;
use examples::run_example_for_key_config;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let key_config = key_config_from_env();
    run_example_for_key_config(&key_config).await?;

    Ok(())
}
