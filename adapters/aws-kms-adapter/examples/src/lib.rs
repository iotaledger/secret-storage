// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use anyhow::anyhow;
use aws_kms_adapter::AwsKmsStorage;
use aws_kms_adapter::KeySpec;
use identity_ecdsa_verifier::EcDSAJwsVerifier;
use identity_eddsa_verifier::EdDSAJwsVerifier;
use identity_iota::core::FromJson as _;
use identity_iota::core::Object;
use identity_iota::core::Url;
use identity_iota::credential::Credential;
use identity_iota::credential::CredentialBuilder;
use identity_iota::credential::DecodedJwtCredential;
use identity_iota::credential::FailFast;
use identity_iota::credential::Jwt;
use identity_iota::credential::JwtCredentialValidationOptions;
use identity_iota::credential::JwtCredentialValidator;
use identity_iota::credential::Subject;
use identity_iota::did::DIDUrl;
use identity_iota::iota::IotaDocument;
use identity_iota::iota::rebased::client::IdentityClient;
use identity_iota::iota::rebased::client::IdentityClientReadOnly;
use identity_iota::iota::rebased::client::IotaKeySignature;
use identity_iota::iota::rebased::utils::request_funds;
use identity_iota::iota_interaction::OptionalSync;
use identity_iota::storage::JwkDocumentExt;
use identity_iota::storage::JwkMemStore;
use identity_iota::storage::JwkStorage;
use identity_iota::storage::KeyIdMemstore;
use identity_iota::storage::KeyType as IdentityStorageKeyType;
use identity_iota::storage::Storage;
use identity_iota::verification::MethodScope;
use identity_iota::verification::VerificationMethod;
use identity_iota::verification::jwk::Jwk;
use identity_iota::verification::jwk::ToJwk;
use identity_iota::did::DID as _;
use identity_iota::storage::JwsSignatureOptions;
use identity_iota::verification::jws::JwsAlgorithm;
use identity_storage::KeyId;
use identity_storage::KeyIdStorage;
use identity_storage::MethodDigest;
use identity_storage::StorageSigner;
use identity_stronghold::StrongholdStorage;
use iota_sdk::IOTA_LOCAL_NETWORK_URL;
use iota_sdk::IotaClient;
use iota_sdk::IotaClientBuilder;
use iota_sdk::types::base_types::IotaAddress;
use iota_sdk::types::base_types::ObjectID;
use iota_sdk::types::crypto::PublicKey;
use iota_sdk_legacy::client::Password;
use iota_sdk_legacy::client::secret::stronghold::StrongholdSecretManager;
use typed_key_signature::TypedKeySignature;
use typed_key_jwk_storage_iota_adapter::IotaCompatibleJwkStorage;
use typed_key_signer_storage_iota_adapter::IotaCompatibleKeyStorage;
use notarization::NotarizationClient;
use notarization::NotarizationClientReadOnly;
use rand::distributions::DistString;
use secret_storage::KeyDelete;
use secret_storage::KeyGet;
use secret_storage::KeySignWithOptions as _;
use secret_storage::Signer;
use serde_json::Value;
use std::env;

pub const TEST_GAS_BUDGET: u64 = 50_000_000;

pub type MemStorage = Storage<JwkMemStore, KeyIdMemstore>;

pub type AwsSignerStorage = IotaCompatibleKeyStorage<AwsKmsStorage>;
pub type AwsStorageWithMemKeyIds = Storage<IotaCompatibleJwkStorage<AwsKmsStorage>, KeyIdMemstore>;

pub struct AwsStorageBundle {
    pub storage: AwsStorageWithMemKeyIds,
    pub signer_storage: AwsSignerStorage,
}

pub struct KeyConfig {
    pub key_id: Option<String>,
    pub jws_algorithm: JwsAlgorithm,
    pub tx_sign_key_spec: KeySpec,
    pub jwk_sign_key_spec: KeySpec,
}

pub async fn create_did_document<K, I, S>(
    identity_client: &IdentityClient<S>,
    storage: &Storage<K, I>,
    key_spec: &KeySpec,
    alg: &JwsAlgorithm,
) -> anyhow::Result<(IotaDocument, String)>
where
    K: JwkStorage,
    I: identity_storage::KeyIdStorage,
    S: Signer<IotaKeySignature> + OptionalSync,
{
    // Create a new DID document with a placeholder DID.
    let mut unpublished: IotaDocument = IotaDocument::new(identity_client.network());
    let verification_method_fragment = unpublished
        .generate_method(
            storage,
            IdentityStorageKeyType::from_static_str(key_spec.into()),
            *alg,
            None,
            MethodScope::VerificationMethod,
        )
        .await?;

    let document = identity_client
        .publish_did_document(unpublished)
        .with_gas_budget(TEST_GAS_BUDGET)
        .build_and_execute(identity_client)
        .await?
        .output;

    Ok((document, verification_method_fragment))
}

pub async fn create_did_document_with_existing_key<K, I, S, SK>(
    identity_client: &IdentityClient<S>,
    storage: &Storage<K, I>,
    signer_storage: &SK,
    key_id: &String,
) -> anyhow::Result<(IotaDocument, String)>
where
    K: JwkStorage,
    I: identity_storage::KeyIdStorage,
    S: Signer<IotaKeySignature> + OptionalSync,
    SK: secret_storage::KeyGet<IotaKeySignature, String> + OptionalSync,
{
    // Create a new DID document with a placeholder DID.
    let mut unpublished: IotaDocument = IotaDocument::new(identity_client.network());

    let public_key = KeyGet::<IotaKeySignature, String>::public_key(signer_storage, key_id)
        .await
        .unwrap();
    let jwk = create_jwk_for_public_key(&public_key);

    // TODO ~~unpublished.id() should just be a placeholder, fix afterwards~~
    //      check afterwards, looks the same in `generate_method`
    let method: VerificationMethod =
        VerificationMethod::new_from_jwk(unpublished.id().clone(), jwk, None).unwrap();

    // Extract data from method before inserting it into the DID document.
    let method_digest: MethodDigest = MethodDigest::new(&method).unwrap();
    let method_id: DIDUrl = method.id().clone();

    // The fragment is always set on a method, so this error will never occur.
    let fragment: String = method_id.fragment().unwrap().to_owned();

    // Insert method into document and handle error upon failure.
    unpublished
        .insert_method(method, MethodScope::VerificationMethod)
        .unwrap();

    // Insert the generated `KeyId` into storage under the computed method digest and handle the error if the
    // operation fails.
    <I as KeyIdStorage>::insert_key_id(
        storage.key_id_storage(),
        method_digest,
        KeyId::new(key_id),
    )
    .await
    .unwrap();

    let document = identity_client
        .publish_did_document(unpublished)
        .with_gas_budget(TEST_GAS_BUDGET)
        .build_and_execute(identity_client)
        .await?
        .output;

    Ok((document, fragment))
}

/// Creates a random stronghold path in the temporary directory, whose exact location is OS-dependent.
pub fn random_stronghold_path() -> PathBuf {
    let mut file = std::env::temp_dir();
    file.push("test_strongholds");
    file.push(rand::distributions::Alphanumeric.sample_string(&mut rand::thread_rng(), 32));
    file.set_extension("stronghold");
    file.to_owned()
}

pub fn get_iota_endpoint() -> String {
    std::env::var("API_ENDPOINT").unwrap_or_else(|_| IOTA_LOCAL_NETWORK_URL.to_string())
}

pub async fn get_iota_client() -> anyhow::Result<IotaClient> {
    let api_endpoint =
        std::env::var("API_ENDPOINT").unwrap_or_else(|_| IOTA_LOCAL_NETWORK_URL.to_string());
    IotaClientBuilder::default()
        .build(&api_endpoint)
        .await
        .map_err(|err| anyhow!(format!("failed to connect to network; {}", err)))
}

pub async fn get_read_only_client() -> anyhow::Result<IdentityClientReadOnly> {
    let iota_client = get_iota_client().await?;
    let package_id = std::env::var("IOTA_IDENTITY_PKG_ID")
        .map_err(|e| {
            anyhow!("env variable IOTA_IDENTITY_PKG_ID must be set in order to run the examples")
                .context(e)
        })
        .and_then(|pkg_str| pkg_str.parse().context("invalid package id"))?;

    IdentityClientReadOnly::new_with_pkg_id(iota_client, package_id)
        .await
        .context("failed to create a read-only IdentityClient")
}


pub async fn get_notarization_client<K, I>(
    signer: StorageSigner<'_, K, I>,
) -> anyhow::Result<NotarizationClient<StorageSigner<'_, K, I>>>
where
    K: JwkStorage,
    I: KeyIdStorage,
{
    let package_id = std::env::var("IOTA_NOTARIZATION_PKG_ID")
        .map_err(|e| {
            anyhow!(
                "env variable IOTA_NOTARIZATION_PKG_ID must be set in order to run this example"
            )
            .context(e)
        })
        .and_then(|pkg_str| pkg_str.parse().context("invalid package id"))?;
    let read_only_client =
        NotarizationClientReadOnly::new_with_pkg_id(get_iota_client().await?, package_id).await?;
    let client = NotarizationClient::new(read_only_client, signer).await?;
    Ok(client)
}

pub fn get_memstorage() -> Result<MemStorage, anyhow::Error> {
    Ok(MemStorage::new(JwkMemStore::new(), KeyIdMemstore::new()))
}

pub fn get_stronghold_storage(
    path: Option<PathBuf>,
) -> Result<Storage<StrongholdStorage, StrongholdStorage>, anyhow::Error> {
    // Stronghold snapshot path.
    let path = path.unwrap_or_else(random_stronghold_path);

    // Stronghold password.
    let password = Password::from("secure_password".to_owned());

    let stronghold = StrongholdSecretManager::builder()
        .password(password.clone())
        .build(path.clone())?;

    // Create a `StrongholdStorage`.
    // `StrongholdStorage` creates internally a `SecretManager` that can be
    // referenced to avoid creating multiple instances around the same stronghold snapshot.
    let stronghold_storage = StrongholdStorage::new(stronghold);

    Ok(Storage::new(
        stronghold_storage.clone(),
        stronghold_storage.clone(),
    ))
}

pub fn pretty_print_json(label: &str, value: &str) {
    let data: Value = serde_json::from_str(value).unwrap();
    let pretty_json = serde_json::to_string_pretty(&data).unwrap();
    println!("--------------------------------------");
    println!("{label}:");
    println!("--------------------------------------");
    println!("{pretty_json} \n");
}

pub async fn create_storage() -> Result<AwsKmsStorage, Box<dyn std::error::Error>> {
    let storage = if let Ok(profile) = env::var("AWS_PROFILE") {
        AwsKmsStorage::from_profile(Some(&profile)).await?
    } else {
        AwsKmsStorage::from_env().await?
    };
    Ok(storage)
}

pub async fn get_funded_client_with_signer<S>(signer: S) -> Result<IdentityClient<S>, anyhow::Error>
where
    S: Signer<IotaKeySignature>,
{
    let sender_address = IotaAddress::from(&Signer::public_key(&signer).await?);

    request_funds(&sender_address).await?;

    let iota_client = get_iota_client().await?;
    let package_id: ObjectID = std::env::var("IOTA_IDENTITY_PKG_ID")
        .map_err(|e| {
            anyhow!("env variable IOTA_IDENTITY_PKG_ID must be set in order to run the examples")
                .context(e)
        })
        .and_then(|pkg_str| pkg_str.parse().context("invalid package id"))?;
    let identity_client = IdentityClient::from_iota_client(iota_client, package_id)
        .await
        .context("failed to create IdentityClient")?
        .with_signer(signer)
        .await?;

    Ok(identity_client)
}

pub async fn get_aws_storage_with_mem_key_ids() -> Result<AwsStorageBundle, anyhow::Error> {
    let aws = create_storage().await.unwrap();
    let signer_storage = IotaCompatibleKeyStorage::new(aws.clone());
    let storage = AwsStorageWithMemKeyIds::new(IotaCompatibleJwkStorage::new(aws), KeyIdMemstore::new());
    Ok(AwsStorageBundle { storage, signer_storage })
}

/// Maps an AWS `KeySpec` to the key type string expected by `IotaCompatibleJwkStorage::generate`
/// and `identity_key_type_to_typed_key_signature` (i.e. the identity SDK key type strings).
pub fn key_spec_to_identity_key_type(key_spec: &KeySpec) -> &'static str {
    match key_spec {
        KeySpec::EccNistEdwards25519 => "Ed25519",
        KeySpec::EccNistP256 => "secp256r1",
        KeySpec::EccSecgP256K1 => "secp256k1",
        _ => panic!("unsupported KeySpec variant: {key_spec}"),
    }
}

fn key_spec_to_jws_algorithm(key_spec: &KeySpec) -> JwsAlgorithm {
    match key_spec {
        KeySpec::EccNistP256         => JwsAlgorithm::ES256,
        KeySpec::EccSecgP256K1       => JwsAlgorithm::ES256K,
        KeySpec::EccNistEdwards25519 => JwsAlgorithm::EdDSA,
        _ => panic!("unsupported KeySpec: {key_spec}"),
    }
}

pub fn key_config_from_env() -> KeyConfig {
    let raw = std::env::var("KEY_ALG").unwrap_or_else(|_| "EdDSA".to_string());
    println!("KEY_ALG={raw}");
    let (key_spec, jws_algorithm) = match raw.as_str() {
        "EdDSA"  => (KeySpec::EccNistEdwards25519, JwsAlgorithm::EdDSA),
        "ES256"  => (KeySpec::EccNistP256,          JwsAlgorithm::ES256),
        "ES256K" => (KeySpec::EccSecgP256K1,         JwsAlgorithm::ES256K),
        _ => panic!("Unsupported KEY_ALG=\"{raw}\". Valid values: EdDSA, ES256, ES256K"),
    };
    KeyConfig {
        jws_algorithm,
        key_id: None,
        tx_sign_key_spec: key_spec,
        jwk_sign_key_spec: key_spec,
    }
}

pub async fn key_config_from_existing_key_id(key_id: String) -> Result<KeyConfig, anyhow::Error> {
    let aws_storage = create_storage().await.map_err(|e| anyhow::anyhow!("{e}"))?;
    let public_key = secret_storage::KeyGet::<TypedKeySignature, String>::public_key(&aws_storage, &key_id).await?;
    let key_spec: KeySpec = public_key.key_type().clone().try_into()?;
    let jws_algorithm = key_spec_to_jws_algorithm(&key_spec);
    println!("Detected algorithm: {jws_algorithm}");
    Ok(KeyConfig {
        key_id: Some(key_id),
        jws_algorithm,
        tx_sign_key_spec: key_spec,
        jwk_sign_key_spec: key_spec,
    })
}

pub async fn run_example_for_key_config(key_config: &KeyConfig) -> Result<(), anyhow::Error> {
    let bundle = get_aws_storage_with_mem_key_ids().await?;
    let storage = &bundle.storage;
    let signer_storage = &bundle.signer_storage;

    let (identity_client, document, vm_fragment, keys_to_delete, tx_key_id) = if let Some(key_id) = &key_config.key_id {
        let signer = signer_storage
            .get_signer_with_options(key_id, &key_config.tx_sign_key_spec.try_into().unwrap())
            .unwrap();
        let identity_client = get_funded_client_with_signer(signer).await?;
        let (document, vm_fragment) =
            create_did_document_with_existing_key(&identity_client, storage, signer_storage, key_id).await?;
        (identity_client, document, vm_fragment, vec![], None)
    } else {
        let tx_key = storage.key_storage()
            .generate(
                IdentityStorageKeyType::from_static_str(key_spec_to_identity_key_type(
                    &key_config.tx_sign_key_spec,
                )),
                key_config.jws_algorithm,
            )
            .await?;
        let tx_key_id = tx_key.key_id.to_string();
        let signer = signer_storage
            .get_signer_with_options(&tx_key_id, &key_config.tx_sign_key_spec.try_into().unwrap())
            .unwrap();
        let identity_client = get_funded_client_with_signer(signer).await?;

        let jwk_key = storage.key_storage()
            .generate(
                IdentityStorageKeyType::from_static_str(key_spec_to_identity_key_type(
                    &key_config.jwk_sign_key_spec,
                )),
                key_config.jws_algorithm,
            )
            .await?;
        let jwk_key_id = jwk_key.key_id.to_string();

        let (document, vm_fragment) =
            create_did_document_with_existing_key(&identity_client, storage, signer_storage, &jwk_key_id).await?;
        (identity_client, document, vm_fragment, vec![jwk_key_id], Some(tx_key_id))
    };

    let resolved = identity_client.resolve_did(document.id()).await?;
    println!("Resolved DID document: {resolved:#}");

    let subject: Subject = Subject::from_json_value(serde_json::json!({
        "id": document.id().as_str(),
        "name": "Alice",
        "degree": {
            "type": "BachelorDegree",
            "name": "Bachelor of Science and Arts",
        },
        "GPA": "4.0",
    }))?;

    let credential: Credential = CredentialBuilder::default()
        .id(Url::parse("https://example.edu/credentials/3732")?)
        .issuer(Url::parse(document.id().as_str())?)
        .type_("UniversityDegreeCredential")
        .subject(subject)
        .build()?;

    let credential_jwt: Jwt = document
        .create_credential_jwt(
            &credential,
            storage,
            &vm_fragment,
            &JwsSignatureOptions::default(),
            None,
        )
        .await?;

    println!("Credential JWT > {}", credential_jwt.as_str());

    let decoded_credential: DecodedJwtCredential<Object> = match key_config.jws_algorithm {
        JwsAlgorithm::EdDSA => {
            JwtCredentialValidator::with_signature_verifier(EdDSAJwsVerifier::default())
                .validate::<_, Object>(
                    &credential_jwt,
                    &document,
                    &JwtCredentialValidationOptions::default(),
                    FailFast::FirstError,
                )
                .unwrap()
        }
        JwsAlgorithm::ES256 | JwsAlgorithm::ES256K => {
            JwtCredentialValidator::with_signature_verifier(EcDSAJwsVerifier::default())
                .validate::<_, Object>(
                    &credential_jwt,
                    &document,
                    &JwtCredentialValidationOptions::default(),
                    FailFast::FirstError,
                )
                .unwrap()
        }
        ref alg => anyhow::bail!("unexpected alg in key config: {alg}"),
    };

    println!("VC successfully validated for algorithm {}", key_config.jws_algorithm);
    println!("Issued credential: {:#}", decoded_credential.credential);

    for key_id in &keys_to_delete {
        println!("Scheduling JWK signing key for deletion: {key_id}");
        KeyDelete::delete(signer_storage, key_id).await?;
    }
    if let Some(id) = tx_key_id {
        println!("Tx signing key kept — reuse with: AWS_KEY_ID={id} in 1_use_existing_key or schedule for deletion with: 2_schedule_key_deletion");
    }

    Ok(())
}

pub fn create_jwk_for_public_key(iota_public_key: &PublicKey) -> Jwk {
    let mut jwk = ToJwk::to_jwk(iota_public_key).unwrap();
    jwk.set_kid(jwk.thumbprint_sha256_b64());

    jwk
}
