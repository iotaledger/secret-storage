// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import { getAwsStorageWithMemMapping } from "./util";

/** Schedule deletion of an AWS KMS key.
 *  Set AWS_KEY_ID to the key ID to delete (e.g. the tx signing key from 0_use_new_keys).
 *  AWS KMS does not delete keys immediately — deletion is scheduled with a mandatory
 *  pending window (default: 7 days), during which it can still be cancelled. */
export async function scheduleKeyDeletion(): Promise<void> {
    const keyId = process.env.AWS_KEY_ID;
    if (!keyId) {
        throw new Error("AWS_KEY_ID must be set to the key ID to schedule for deletion.");
    }
    console.log(`AWS_KEY_ID=${keyId}`);

    const { awsStorage } = await getAwsStorageWithMemMapping();

    await awsStorage.delete(keyId);
    console.log(`Key scheduled for deletion: ${keyId}`);
}
