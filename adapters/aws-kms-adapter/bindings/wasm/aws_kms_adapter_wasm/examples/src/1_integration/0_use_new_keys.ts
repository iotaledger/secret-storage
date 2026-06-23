// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import { JwsAlgorithm } from "@iota/identity-wasm/node";
import { IotaClient } from "@iota/iota-sdk/client";
import {
  createAndValidateCredential,
  createDocumentForNetwork,
  getAwsStorageWithMemMapping,
  getFundedClient,
  NETWORK_URL,
} from "./util";

function algFromEnv(): JwsAlgorithm {
  const raw = process.env.KEY_ALG ?? JwsAlgorithm.EdDSA;
  console.log(`KEY_ALG=${raw}`);
  switch (raw) {
    case JwsAlgorithm.EdDSA:
      return JwsAlgorithm.EdDSA;
    case JwsAlgorithm.ES256:
      return JwsAlgorithm.ES256;
    case JwsAlgorithm.ES256K:
      return JwsAlgorithm.ES256K;
    default:
      throw new Error(
        `Unsupported KEY_ALG="${raw}". Valid values: ${JwsAlgorithm.EdDSA}, ${JwsAlgorithm.ES256}, ${JwsAlgorithm.ES256K}`,
      );
  }
}

/** Create two new AWS KMS keys (tx signing + JWK), publish a DID Document, and sign a credential.
 *  Algorithm defaults to EdDSA — override with the KEY_ALG env var (EdDSA, ES256, ES256K).
 *  The tx signing key ID is logged as AWS_KEY_ID=<id> for use in 1_use_existing_key.
 *  The JWK signing key is scheduled for deletion at the end of the run. */
export async function useNewKeys(): Promise<void> {
  const iotaClient = new IotaClient({ url: NETWORK_URL });
  const network = await iotaClient.getChainIdentifier();

  const alg = algFromEnv();

  const { storage, awsStorage } = await getAwsStorageWithMemMapping();

  const { identityClient, txKeyId } = await getFundedClient(
    storage,
    awsStorage,
    alg,
  );
  const { unpublished, fragment, jwkKeyId } = await createDocumentForNetwork(
    storage,
    network,
    alg,
  );

  try {
    const { output: identity } = await identityClient
      .createIdentity(unpublished)
      .finish()
      .buildAndExecute(identityClient);
    const document = identity.didDocument();

    const resolved = await identityClient.resolveDid(document.id());
    console.log(`Resolved DID document: ${JSON.stringify(resolved, null, 2)}`);

    await createAndValidateCredential(document, storage, fragment, alg);
  } finally {
    console.log(`Scheduling JWK signing key for deletion: ${jwkKeyId}`);
    await awsStorage.delete(jwkKeyId);
    console.log(
      `Tx signing key kept — reuse with: AWS_KEY_ID=${txKeyId} in 1_use_existing_key or schedule for deletion with: 2_schedule_key_deletion`,
    );
  }
}
