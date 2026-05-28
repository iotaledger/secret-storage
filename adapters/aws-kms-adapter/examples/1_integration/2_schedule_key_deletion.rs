// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use examples::create_storage;
use secret_storage::KeyDelete;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let key_id = std::env::var("AWS_KEY_ID")
        .map_err(|_| anyhow::anyhow!("AWS_KEY_ID must be set to the key ID to schedule for deletion"))?;
    println!("AWS_KEY_ID={key_id}");

    let aws_storage = create_storage().await.map_err(|e| anyhow::anyhow!("{e}"))?;
    KeyDelete::delete(&aws_storage, &key_id).await?;

    println!("Key scheduled for deletion: {key_id}");

    Ok(())
}
