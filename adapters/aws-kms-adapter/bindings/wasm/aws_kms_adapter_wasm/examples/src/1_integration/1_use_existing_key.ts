// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import { IotaClient } from "@iota/iota-sdk/client";
import {
    algFromKeyType,
    createAndValidateCredential,
    createDocumentWithExistingKey,
    getAwsStorageWithMemMapping,
    getClientWithExistingKey,
    NETWORK_URL,
} from "./util";

/** Use an existing AWS KMS key to publish a DID Document and sign a credential.
 *  Set AWS_KEY_ID to a key ID from the output of 0_use_new_keys. */
export async function useExistingKey(): Promise<void> {
    const iotaClient = new IotaClient({ url: NETWORK_URL });
    const network = await iotaClient.getChainIdentifier();

    const { storage, awsStorage, iotaCompatibleStorage } = await getAwsStorageWithMemMapping();

    const keyId = process.env.AWS_KEY_ID;
    if (!keyId) {
        throw new Error("AWS_KEY_ID must be set to an existing AWS KMS key ID.");
    }
    console.log(`AWS_KEY_ID=${keyId}`);

    const { keyType } = await awsStorage.publicKey(keyId);
    const alg = algFromKeyType(keyType);
    console.log(`Detected algorithm: ${alg}`);

    const identityClient = await getClientWithExistingKey(awsStorage, keyId);
    const [document, fragment] = await createDocumentWithExistingKey(
        identityClient, storage, iotaCompatibleStorage, keyId, network,
    );

    const resolved = await identityClient.resolveDid(document.id());
    console.log(`Resolved DID document: ${JSON.stringify(resolved, null, 2)}`);

    await createAndValidateCredential(document, storage, fragment, alg);
}
