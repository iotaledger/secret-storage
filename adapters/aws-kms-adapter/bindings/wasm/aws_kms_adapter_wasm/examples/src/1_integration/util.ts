// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import {
    Credential,
    EcDSAJwsVerifier,
    EdDSAJwsVerifier,
    FailFast,
    IdentityClient,
    IdentityClientReadOnly,
    IotaDocument,
    Jwk,
    JwsAlgorithm,
    JwsSignatureOptions,
    JwtCredentialValidationOptions,
    JwtCredentialValidator,
    KeyIdMemStore,
    MethodDigest,
    MethodScope,
    Storage,
    VerificationMethod,
} from "@iota/identity-wasm/node";
import { getFullnodeUrl, IotaClient } from "@iota/iota-sdk/client";
import { getFaucetHost, requestIotaFromFaucetV0 } from "@iota/iota-sdk/faucet";
import { AwsKmsStorage } from "@iota/aws_kms_adapter_wasm/node/aws_kms_adapter_wasm";
import type { KeyType } from "@iota/aws_kms_adapter_wasm/node/aws_kms_adapter_wasm";
import { IotaCompatibleJwkStorage, type PublicJwk } from "@iota/typed-key-jwk-storage-iota-adapter-wasm/node/typed_key_jwk_storage_iota_adapter_wasm";
import { IotaCompatibleSigner } from "@iota/typed-key-signer-storage-iota-adapter-wasm/node/typed_key_signer_storage_iota_adapter_wasm";

export const IOTA_IDENTITY_PKG_ID = globalThis?.process?.env?.IOTA_IDENTITY_PKG_ID
    ?? (() => { throw new Error("Missing required environment variable: IOTA_IDENTITY_PKG_ID"); })();
export const NETWORK_NAME_FAUCET = globalThis?.process?.env?.NETWORK_NAME_FAUCET || "localnet";
export const NETWORK_URL = getFullnodeUrl(NETWORK_NAME_FAUCET);


const AWS_REGION = process.env.AWS_REGION
    ?? (() => { throw new Error("Missing required environment variable: AWS_REGION"); })();
const AWS_ACCESS_KEY_ID = process.env.AWS_ACCESS_KEY_ID
    ?? (() => { throw new Error("Missing required environment variable: AWS_ACCESS_KEY_ID"); })();
const AWS_SECRET_ACCESS_KEY = process.env.AWS_SECRET_ACCESS_KEY
    ?? (() => { throw new Error("Missing required environment variable: AWS_SECRET_ACCESS_KEY"); })();

// Observed createIdentity gas cost: ~9_010_400 nanos. MIN_BALANCE is ~5x that as a safety margin.
export const MIN_BALANCE = BigInt(50_000_000);

export async function getAwsStorageWithMemMapping(): Promise<{ storage: Storage; awsStorage: AwsKmsStorage; iotaCompatibleStorage: IotaCompatibleJwkStorage }> {
    const awsStorage = await AwsKmsStorage.create(AWS_REGION, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY);
    const iotaCompatibleStorage = new IotaCompatibleJwkStorage(awsStorage);
    const storage = new Storage(iotaCompatibleStorage as any, new KeyIdMemStore());
    return { storage, awsStorage, iotaCompatibleStorage };
}



export async function requestFunds(address: string) {
    await requestIotaFromFaucetV0({
        host: getFaucetHost(NETWORK_NAME_FAUCET),
        recipient: address,
    });
}

function keyTypeForAlg(alg: JwsAlgorithm): string {
    switch (alg) {
        case JwsAlgorithm.EdDSA:  return "Ed25519";
        case JwsAlgorithm.ES256:  return "secp256r1";
        case JwsAlgorithm.ES256K: return "secp256k1";
        default: throw new Error(`unsupported algorithm: ${alg}`);
    }
}

function algToDerKeyType(alg: JwsAlgorithm): KeyType {
    switch (alg) {
        case JwsAlgorithm.EdDSA:  return "Ed25519DerEncoded";
        case JwsAlgorithm.ES256:  return "Secp256r1DerEncoded";
        case JwsAlgorithm.ES256K: return "Secp256k1DerEncoded";
        default: throw new Error(`unsupported algorithm: ${alg}`);
    }
}

export async function createDocumentForNetwork(storage: Storage, network: string, alg: JwsAlgorithm): Promise<{ unpublished: IotaDocument; fragment: string; jwkKeyId: string }> {
    const unpublished = new IotaDocument(network);

    const fragment = await unpublished.generateMethod(
        storage,
        keyTypeForAlg(alg),
        alg,
        "#key-1",
        MethodScope.VerificationMethod(),
    );

    const method = unpublished.resolveMethod(fragment)!;
    const digest = new MethodDigest(method);
    const jwkKeyId = await storage.keyIdStorage().getKeyId(digest);

    return { unpublished, fragment, jwkKeyId };
}

export function algFromKeyType(keyType: KeyType): JwsAlgorithm {
    if (keyType === "Ed25519DerEncoded") return JwsAlgorithm.EdDSA;
    if (keyType === "Secp256r1DerEncoded") return JwsAlgorithm.ES256;
    if (keyType === "Secp256k1DerEncoded") return JwsAlgorithm.ES256K;
    throw new Error(`unsupported key type: ${JSON.stringify(keyType)}`);
}

export async function createAndValidateCredential(
    document: IotaDocument,
    storage: Storage,
    fragment: string,
    alg: JwsAlgorithm,
): Promise<void> {
    const subject = {
        id: document.id(),
        name: "Alice",
        degree: {
            type: "BachelorDegree",
            name: "Bachelor of Science and Arts",
        },
        GPA: "4.0",
    };

    const unsignedVc = new Credential({
        id: "https://example.edu/credentials/3732",
        type: "UniversityDegreeCredential",
        issuer: document.id(),
        credentialSubject: subject,
    });

    const credentialJwt = await document.createCredentialJwt(
        storage,
        fragment,
        unsignedVc,
        new JwsSignatureOptions(),
    );
    console.log(`Credential JWT > ${credentialJwt.toString()}`);

    const verifier = alg === JwsAlgorithm.EdDSA ? new EdDSAJwsVerifier() : new EcDSAJwsVerifier();
    const decoded = new JwtCredentialValidator(verifier).validate(
        credentialJwt,
        document,
        new JwtCredentialValidationOptions(),
        FailFast.FirstError,
    );

    console.log(`VC successfully validated for algorithm ${alg}`);
    console.log(`Issued credential: ${JSON.stringify(decoded.intoCredential(), null, 2)}`);
}

export async function createDocumentWithExistingKey(
    identityClient: IdentityClient,
    storage: Storage,
    iotaCompatibleStorage: IotaCompatibleJwkStorage,
    keyId: string,
    network: string,
): Promise<[IotaDocument, string]> {
    const unpublished = new IotaDocument(network);

    const jwkData: PublicJwk = await iotaCompatibleStorage.publicKeyJwk(keyId);
    const jwk = Jwk.fromJSON(jwkData);

    const method = VerificationMethod.newFromJwk(unpublished.id(), jwk);
    const fragment = method.id().fragment()!;

    unpublished.insertMethod(method, MethodScope.VerificationMethod());

    // Register keyId → method digest in KeyIdMemStore so the storage can locate
    // this key for future signing operations (e.g. JWT credential issuance).
    const methodDigest = new MethodDigest(method);
    await storage.keyIdStorage().insertKeyId(methodDigest, keyId);

    const { output: identity } = await identityClient
        .createIdentity(unpublished)
        .finish()
        .buildAndExecute(identityClient);

    return [identity.didDocument(), fragment];
}

export async function getClientWithExistingKey(awsStorage: AwsKmsStorage, keyId: string): Promise<IdentityClient> {
    const iotaClient = new IotaClient({ url: NETWORK_URL });
    const identityClientReadOnly = await IdentityClientReadOnly.create(iotaClient, IOTA_IDENTITY_PKG_ID);

    const { keyType } = await awsStorage.publicKey(keyId);
    const rawSigner = awsStorage.getSignerWithOptions(keyId, keyType);
    const signer = new IotaCompatibleSigner(rawSigner);
    const identityClient = await IdentityClient.create(identityClientReadOnly, signer as any);

    let balance = await iotaClient.getBalance({ owner: identityClient.senderAddress() });
    if (BigInt(balance.totalBalance) < MIN_BALANCE) {
        await requestFunds(identityClient.senderAddress());
        balance = await iotaClient.getBalance({ owner: identityClient.senderAddress() });
        if (BigInt(balance.totalBalance) < MIN_BALANCE) {
            throw new Error(`Balance ${balance.totalBalance} is below minimum ${MIN_BALANCE} after requesting funds`);
        }
    }
    console.log(`Balance: ${balance.totalBalance} for owner ${identityClient.senderAddress()}`);

    return identityClient;
}

export async function getFundedClient(storage: Storage, awsStorage: AwsKmsStorage, alg: JwsAlgorithm): Promise<{ identityClient: IdentityClient; txKeyId: string }> {
    const iotaClient = new IotaClient({ url: NETWORK_URL });
    const identityClientReadOnly = await IdentityClientReadOnly.create(iotaClient, IOTA_IDENTITY_PKG_ID);

    const generate = await storage.keyStorage().generate(keyTypeForAlg(alg), alg);
    const txKeyId = generate.keyId();
    console.log(`Generated tx signing key — AWS_KEY_ID=${txKeyId}`);

    const rawSigner = awsStorage.getSignerWithOptions(txKeyId, algToDerKeyType(alg));
    const signer = new IotaCompatibleSigner(rawSigner);
    const identityClient = await IdentityClient.create(identityClientReadOnly, signer as any);

    let balance = await iotaClient.getBalance({ owner: identityClient.senderAddress() });
    if (BigInt(balance.totalBalance) < MIN_BALANCE) {
        await requestFunds(identityClient.senderAddress());
        balance = await iotaClient.getBalance({ owner: identityClient.senderAddress() });
        if (BigInt(balance.totalBalance) < MIN_BALANCE) {
            throw new Error(`Balance ${balance.totalBalance} is below minimum ${MIN_BALANCE} after requesting funds`);
        }
    }
    console.log(`Balance: ${balance.totalBalance} for owner ${identityClient.senderAddress()}`);

    return { identityClient, txKeyId };
}
