# IOTA Secret Storage Repository Refactoring

## Overview of Changes

This document describes the complete refactoring of the `secret-storage` repository according to hexagonal architecture principles, with the implementation of an AWS KMS adapter and a modular system for adapter selection.

## Implemented Architecture

### Repository Structure

The repository has been reorganized following hexagonal architecture:

```
secret-storage/
├── core/secret-storage/                             # Core domain - pure traits
├── adapters/aws-kms-adapter/         # AWS KMS adapter
├── applications/storage-factory/     # Factory pattern for adapter selection
├── .env.example                      # Environment variables template
└── doc/refactor.en.md               # This documentation
```

### Architectural Principles

1. **Core Domain**: Contains only business logic and trait definitions
2. **Adapters**: Specific implementations for different technologies (AWS KMS, filesystem, passkey)
3. **Applications**: Use case orchestration and adapter selection

## Implemented Components

### 1. Core Traits (core/secret-storage/)

Existing traits have been moved without modifications to the core module:

- `KeysStorage` - Main trait combining all functionalities
- `KeyGenerate` - Generation of new key pairs
- `KeySign` - Signing data with stored keys
- `KeyDelete` - Key deletion
- `KeyExist` - Key existence verification
- `KeyGet` - Public key retrieval
- `Signer` - Low-level signing interface
- `SignatureScheme` - Signature scheme definitions

### 2. AWS KMS Adapter (adapters/aws-kms-adapter)

Complete implementation for integration with AWS Key Management Service:

#### Main Features:
- **Configuration from environment variables**
- **Key generation with ECC_NIST_P256** (default)
- **ECDSA_SHA_256 signatures**
- **IAM integration** for access controls
- **Audit logging** via CloudTrail
- **Typed error handling**

#### Structure:
```
adapters/aws-kms-adapter/
├── src/
│   ├── config.rs      # AWS configuration
│   ├── error.rs       # Error handling
│   ├── signer.rs      # Signer implementation
│   ├── storage.rs     # Storage trait implementation
│   ├── lib.rs         # Main module
│   └── utils/         # Modular utilities
│       ├── aws_client.rs    # AWS client creation
│       ├── key_utils.rs     # Key identification utilities
│       ├── kms_operations.rs # Common KMS operations
│       └── mod.rs           # Module exports
├── examples/
│   ├── key_deletion_demo.rs # Key lifecycle management
│   ├── secp256r1_demo.rs    # Curve-specific operations
│   └── signing_demo.rs      # Basic signing workflow
└── Cargo.toml
```

### 3. Storage Factory (applications/storage-factory)

Builder pattern system for explicit adapter selection:

#### Functionality:
- **Explicit selection** with dedicated `build_*()` methods
- **Multi-auth support** for AWS Profile vs. direct credentials
- **Manual configuration** for specific adapters
- **Extensibility** for future adapters

## Configuration and Usage

### 1. Environment Variables Configuration

Copy the environment variables template:
```bash
cp .env.example .env
```

You have **3 options** for AWS authentication:

#### Option A: Direct Credentials
```bash
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key
AWS_REGION=eu-west-1
```

#### Option B: AWS Profile (Recommended for IAM roles)
```bash
AWS_PROFILE=your-profile-name
AWS_REGION=eu-west-1
```

This uses the profile configured in `~/.aws/config`:
```ini
[profile developer]
role_arn = arn:aws:iam::304431203043:role/DeveloperFullAccessRole
source_profile = default
region = eu-west-1
```

#### Option C: Temporary Environment Variables
```bash
export AWS_PROFILE=your-profile-name
export AWS_REGION=eu-west-1
```

#### Additional Configurations:
```bash
# Optional: Existing KMS key ID
KMS_KEY_ID=arn:aws:kms:eu-west-1:304431203043:key/12345678-1234-1234-1234-123456789012

# Optional: Specific KMS key to use (if not generating new ones)
# KMS_KEY_ALIAS=alias/my-existing-key
```

### 2. Basic Usage with AWS KMS

```rust
use storage_factory::StorageBuilder;
use secret_storage_core::{KeyGenerate, KeySign, Signer};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Auto-detection of adapter from environment variables
    let storage = StorageBuilder::new().aws_kms().build_aws_kms().await?;
    
    // Generate a new key pair
    let (key_id, public_key) = storage.generate_key().await?;
    println!("Key generated with ID: {}", key_id);
    
    // Get a signer for the key
    let signer = storage.get_signer(&key_id)?;
    
    // Sign data
    let data = b"Data to sign with IOTA";
    let signature = signer.sign(&data.to_vec()).await?;
    
    println!("Signature created: {} bytes", signature.len());
    Ok(())
}
```

### 3. Manual Adapter Configuration

```rust
use storage_factory::StorageBuilder;
use aws_kms_adapter::AwsKmsStorage;

// Option 1: Explicit configuration via StorageBuilder
let storage = StorageBuilder::new()
    .aws_kms()
    .with_region("eu-west-1".to_string())
    .with_kms_key_id("your-kms-key".to_string())
    .build()
    .await?;

// Option 2: Direct usage with AWS profile
let storage = AwsKmsStorage::with_profile(Some("developer")).await?;

// Option 3: Direct usage with profile from environment variable
let profile = std::env::var("AWS_PROFILE").ok();
let storage = AwsKmsStorage::with_profile(profile.as_deref()).await?;
```

## IOTA SDK Integration

### Transaction Signing Example

```rust
use iota_sdk::{IotaClient, types::TransactionData};
use storage_factory::StorageBuilder;
use secret_storage_core::{KeySign, Signer};

async fn sign_iota_transaction(
    client: &IotaClient,
    transaction_data: TransactionData,
    key_id: &str
) -> Result<(), Box<dyn std::error::Error>> {
    // Initialize storage from environment configuration
    let storage = StorageBuilder::new().aws_kms().build_aws_kms().await?;
    
    // Get signer for specific key
    let signer = storage.get_signer(key_id)?;
    
    // Get data to sign from IOTA transaction
    let data_to_sign = transaction_data.get_data_to_sign();
    
    // Sign data using AWS KMS
    let signature = signer.sign(&data_to_sign).await?;
    
    // Create complete transaction with signature
    let signed_transaction = transaction_data.with_signature(signature);
    
    // Submit transaction via IOTA SDK
    let result = client.submit_transaction(signed_transaction).await?;
    
    println!("Transaction submitted: {:?}", result);
    Ok(())
}

// Example with multiple key management
async fn enterprise_key_management() -> Result<(), Box<dyn std::error::Error>> {
    let storage = StorageBuilder::new().aws_kms().build_aws_kms().await?;
    
    // Generate keys for different purposes
    let (admin_key_id, _) = storage.generate_key().await?;
    let (user_key_id, _) = storage.generate_key().await?;
    
    // Use keys for different operations
    let admin_signer = storage.get_signer(&admin_key_id)?;
    let user_signer = storage.get_signer(&user_key_id)?;
    
    // Administrative signature
    let admin_signature = admin_signer.sign(&b"admin_operation".to_vec()).await?;
    
    // User signature
    let user_signature = user_signer.sign(&b"user_operation".to_vec()).await?;
    
    Ok(())
}
```

### Custom Implementation for IOTA

```rust
// IOTA-specific adapter
pub struct IotaSignatureScheme;

impl SignatureScheme for IotaSignatureScheme {
    type PublicKey = iota_sdk::types::PublicKey;
    type Signature = iota_sdk::types::Signature;
    type Input = Vec<u8>; // Transaction hash
}

// Wrapper to integrate with IOTA SDK
pub struct IotaKmsStorage {
    inner: AwsKmsStorage,
}

impl IotaKmsStorage {
    pub async fn from_env() -> Result<Self> {
        let inner = AwsKmsStorage::from_env().await?;
        Ok(Self { inner })
    }
    
    pub async fn sign_transaction(
        &self, 
        key_id: &str, 
        transaction: &TransactionData
    ) -> Result<iota_sdk::types::Signature> {
        let signer = self.inner.get_signer(key_id)?;
        let hash = transaction.get_data_to_sign();
        let raw_signature = signer.sign(&hash).await?;
        
        // Convert raw AWS signature to IOTA format
        let iota_signature = self.convert_signature(raw_signature)?;
        Ok(iota_signature)
    }
    
    fn convert_signature(&self, aws_sig: Vec<u8>) -> Result<iota_sdk::types::Signature> {
        // Implement conversion from AWS KMS signature to IOTA format
        // This depends on the specific format required by IOTA SDK
        todo!("Implement IOTA-specific signature conversion")
    }
}
```

## Testing

### Testing with Real AWS

```bash
# Configure AWS credentials
export AWS_REGION=eu-west-1
export AWS_PROFILE=your-profile-name

# Run basic tests
cargo test --package aws-kms-adapter

# Run integration tests (requires real AWS KMS access)
export RUN_INTEGRATION_TESTS=true
cargo test --package aws-kms-adapter integration
```

### Running Examples

```bash
# Complete IOTA workflow with dynamic key generation and auto-faucet
AWS_REGION=eu-west-1 cargo run --package storage-factory --example iota_kms_demo

# IOTA address generation and faucet funding
AWS_REGION=eu-west-1 cargo run --package storage-factory --example iota_address_faucet_demo

# AWS KMS key deletion demonstration
cargo run --package aws-kms-adapter --example key_deletion_demo

# secp256r1 signature demonstration
cargo run --package aws-kms-adapter --example secp256r1_demo

# Basic signing operations
cargo run --package aws-kms-adapter --example signing_demo
```

## 🏢 Authentication Strategies for Enterprise Services

### 1. **VM on AWS (EC2 Instance Roles)**
```rust
// VM has an associated Instance Profile
let storage = AwsKmsStorage::for_container_service().await?;
```

**IAM Configuration:**
- Create IAM role (`IotaSecretStorageInstanceRole`)
- Attach appropriate KMS policy
- Associate role with VM's Instance Profile
- **No hardcoded credentials needed**

### 2. **Container on ECS (Task Roles)**
```rust
// ECS task has an associated Task Role
let storage = AwsKmsStorage::for_container_service().await?;
```

**ECS Configuration:**
```json
{
  "taskRoleArn": "arn:aws:iam::304431203043:role/IotaSecretStorageTaskRole",
  "containerDefinitions": [{
    "name": "iota-service",
    "environment": [
      {"name": "AWS_REGION", "value": "eu-west-1"}
    ]
  }]
}
```

### 3. **Container on Kubernetes/EKS (IRSA)**
```rust
// Pod has Service Account with IRSA
let storage = AwsKmsStorage::for_container_service().await?;
```

**Kubernetes Configuration:**
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: iota-secret-storage
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::304431203043:role/IotaSecretStorageServiceRole
---
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      serviceAccountName: iota-secret-storage
      containers:
      - name: iota-service
        env:
        - name: AWS_REGION
          value: "eu-west-1"
```

### 4. **Cross-Account Role Assumption**
```rust
// For cross-account access
let storage = AwsKmsStorage::with_assumed_role(
    "arn:aws:iam::304431203043:role/DeveloperFullAccessRole",
    "iota-service-session",
    Some("eu-west-1")
).await?;
```

**Environment variables for Cross-Account:**
```bash
# Target role to assume
TARGET_ROLE_ARN=arn:aws:iam::304431203043:role/DeveloperFullAccessRole
SERVICE_NAME=iota-secret-storage-service
AWS_REGION=eu-west-1
```

### 5. **Minimal IAM Policy for KMS**
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "kms:CreateKey",
                "kms:DescribeKey", 
                "kms:GetPublicKey",
                "kms:Sign",
                "kms:ScheduleKeyDeletion"
            ],
            "Resource": "arn:aws:kms:eu-west-1:304431203043:key/*"
        }
    ]
}
```

## Architecture Benefits

### 1. Modularity
- Each adapter is a separate crate
- Easy to add new providers (Azure, Google Cloud, HSM)
- Isolated dependencies for each implementation

### 2. Security
- **Enclave Principle**: private keys never leave secure environments
- **Principle of Least Privilege**: atomic and specific permissions
- **Explicit Boundaries**: clear separation between provider and user code

### 3. Ease of Use
- Auto-detection of available adapters
- Configuration via environment variables
- Uniform API for all adapters

### 4. Enterprise-Ready
- Automatic audit logging (CloudTrail for AWS)
- Granular access controls (IAM)
- Multi-tenant support (planned)
- Key rotation (planned)

## Future Adapters Roadmap

1. **Filesystem Adapter** - For development and testing
2. **Passkey Adapter** - Self-custody client-side
3. **DFNS Adapter** - Multi-party computation
4. **Azure Key Vault** - Microsoft cloud HSM
5. **Google Cloud KMS** - Google cloud key management
6. **Hardware HSM** - Direct HSM integration

## Security Considerations

- Private keys never leave secure environments (KMS, HSM, enclaves)
- Minimal permissions via IAM policies
- Environment variable validation
- Secure error handling without key material exposure
- Audit logging for compliance

This refactoring provides a solid foundation for enterprise key management with IOTA's Trust Framework, maintaining flexibility for different deployment scenarios and security requirements.