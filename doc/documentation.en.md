# Secret Storage - Repository Documentation

## Overview

**Secret Storage** is a modular Rust library implementing hexagonal architecture for secure cryptographic key management. The system provides a flexible, trait-based foundation that enables horizontal scaling across diverse key management strategies, from cloud HSMs to third-party MPC providers.

## Hexagonal Architecture

The project implements clean architecture principles with three distinct layers:

### Core Layer (`core/secret-storage`)
**Pure business logic and trait definitions** - The heart of the system containing domain-driven interfaces without external dependencies.

### Adapter Layer (`adapters/`)
**Infrastructure implementations** - Concrete implementations of core traits for different key management strategies.

### Application Layer (`applications/`)
**Use case orchestration** - Higher-level services that combine adapters and provide business workflows.

## Repository Structure

```
secret-storage/
├── core/secret-storage/           # 🏛️  CORE: Pure business logic
│   ├── src/
│   │   ├── storage.rs            # Core storage traits (KeyGenerate, KeySign, etc.)
│   │   ├── signer.rs             # Signing interface definitions
│   │   ├── signature_scheme.rs   # Signature scheme abstractions
│   │   └── error.rs              # Domain error definitions
│   └── Cargo.toml
├── adapters/                      # 🔌 ADAPTERS: Infrastructure implementations
│   ├── aws-kms-adapter/          # AWS KMS implementation
│   ├── dfns-adapter/             # 🚧 Future: Third party MPC integration
│   └── file-storage-adapter/     # 🚧 Future: Local file-based storage
└── applications/                  # 🏗️  APPLICATIONS: Business orchestration
    └──  storage-factory/          # Auto-detection and adapter selection
```

## Core Traits: The Foundation

The core layer defines **technology-agnostic traits** that serve as contracts for any key management implementation. These traits enable the system's horizontal scalability by providing consistent interfaces regardless of the underlying infrastructure.

### 1. SignatureScheme
**Foundation contract** defining cryptographic primitives:
```rust
pub trait SignatureScheme {
    type PublicKey;     // Public key representation
    type Signature;     // Signature format
    type Input;         // Input data type for signing
}
```

### 2. Storage Traits - Atomic Operations
Following the **principle of least privilege**, each trait represents a specific capability:

#### KeyGenerate - Key Creation
```rust
async fn generate_key(&self) -> Result<(I, K::PublicKey)>
```
- Creates new cryptographic key pairs
- Returns key identifier and public key
- **Adapters**: AWS KMS, HSM modules, MPC networks

#### KeySign - Signing Operations  
```rust
fn get_signer(&self, key_id: &I) -> Result<Box<dyn Signer<K>>>
```
- Provides signer interface for specific keys
- Maintains enclave principle (private keys never leave secure boundaries)
- **Adapters**: Cloud HSMs, hardware tokens

#### KeyDelete - Secure Disposal
```rust
async fn delete_key(&self, key_id: &I) -> Result<()>
```
- Secure key destruction with compliance guarantees
- **Adapters**: KMS deletion policies, HSM purging, MPC key shares destruction

#### KeyExist & KeyGet - Key Management
```rust
async fn exist(&self, key_id: &I) -> Result<bool>
async fn public_key(&self, key_id: &I) -> Result<K::PublicKey>
```
- Non-destructive key operations
- Enable key lifecycle management

### 3. Signer Interface
**Universal signing abstraction**:
```rust
pub trait Signer<K: SignatureScheme> {
    async fn sign(&self, input: &K::Input) -> Result<K::Signature>;
    fn public_key(&self) -> &K::PublicKey;
    fn key_id(&self) -> &str;
}
```

## Adapter Layer: Infrastructure Implementations

The adapter layer bridges **core business logic** with **concrete infrastructure**. Each adapter implements the core traits for a specific key management strategy, enabling seamless horizontal scaling.

### Current Implementation

#### AWS KMS Adapter (`adapters/aws-kms-adapter/`)
**Production-ready cloud HSM integration**:
- ✅ **secp256r1 (P-256)** support for IOTA blockchain
- ✅ **Signature canonicalization** for ECDSA compliance
- ✅ **IAM-based access control** with least privilege policies
- ✅ **Audit logging** through CloudTrail
- ✅ **Multi-region support** with automatic failover

### Future Horizontal Scaling

The modular architecture enables **effortless expansion** to new key management strategies:

#### WASM Adapter (`adapters/wasm-adapter/`) 🚧
**WebAssembly runtime integration**:
- Client-side key generation and signing
- Browser sandboxing for security
- Near-native performance in web environments
- Cross-language compatibility

#### MPC Adapters 🚧
**Multi-Party Computation networks**:

##### Dfinity (DFNS) Adapter (`adapters/dfns-adapter/`)
- Internet Computer blockchain integration
- Threshold cryptography for decentralized signing
- Chain-key cryptography support
- Cross-chain signature compatibility

##### Generic MPC Adapter (`adapters/mpc-adapter/`)
- Fireblocks, Coinbase Prime, BitGo integration
- Enterprise-grade custody solutions
- Regulatory compliance (SOC2, FIPS 140-2)
- Multi-signature governance

#### Hardware Security Modules 🚧
- **TPM Adapter**: Trusted Platform Module integration
- **HSM Adapter**: Dedicated hardware security modules
- **Secure Enclave**: Apple/ARM TrustZone integration

## Application Layer: Business Orchestration

The application layer **combines adapters** and provides **high-level business workflows**.

### Storage Factory (`applications/storage-factory/`)
**Explicit adapter selection with builder pattern**:
- ✅ **Builder pattern**: Type-safe adapter configuration with dedicated build methods
- ✅ **Explicit selection**: Clear `build_aws_kms()` and other type-safe build methods
- ✅ **Multi-auth support**: Automatic detection of AWS Profile vs. direct credentials
- ✅ **Environment configuration**: Region, key ID, and other adapter-specific settings

### Future Application Services 🚧

#### Key Manager (`applications/key-manager/`)
**Advanced key lifecycle management**:
- Key rotation policies and automation
- Backup and recovery workflows
- Compliance reporting and auditing
- Multi-adapter key federation

#### Transaction Orchestrator (`applications/transaction-orchestrator/`)
**Blockchain-agnostic transaction management**:
- Cross-chain transaction coordination
- Gas optimization and fee management
- Transaction batching and sequencing
- Retry logic and error recovery

## Horizontal Scalability Strategy

### 1. **Plugin Architecture**
Each adapter is a **self-contained plugin** that can be:
- Developed independently
- Deployed separately
- Configured at runtime
- Hot-swapped without downtime

### 2. **Trait Composition**
Core traits can be **composed** to create specialized capabilities:
```rust
// Multi-signature governance
trait MultiSigStorage: KeyGenerate + KeySign + KeyDelete + KeyGet {}

// Read-only audit interface  
trait AuditStorage: KeyExist + KeyGet {}

// High-security operations
trait SecureStorage: KeyGenerate + KeyDelete {}
```

### 3. **Adapter Federation**
Multiple adapters can work together:
- **Primary/Secondary**: AWS KMS primary with HSM backup
- **Sharding**: Different keys across different providers
- **MPC Coordination**: Threshold signatures across multiple adapters

### 4. **Explicit Adapter Selection**
Applications use explicit, type-safe builder methods:
```rust
// AWS KMS with explicit configuration
let aws_storage = StorageBuilder::new()
    .aws_kms()
    .with_region("eu-west-1".to_string())
    .build_aws_kms()
    .await?;

// Future: File system storage
let fs_storage = StorageBuilder::new()
    .file_system()
    .build_file_system()
    .await?;
```

## Security Architecture

### Enclave Principle
**Private keys never leave secure boundaries**:
- AWS KMS: Keys remain in FIPS 140-2 Level 3 HSMs
- Hardware tokens: Keys stored in secure enclaves (Secure Enclave, TPM)
- MPC: Keys exist only as distributed shares

### Principle of Least Privilege
**Atomic permissions** enable fine-grained access control:
- Generate keys without signing capability
- Sign without key management permissions
- Read public keys without destructive operations

### Explicit Boundaries
**Clear separation** between layers:
- Core: Pure business logic, no infrastructure dependencies
- Adapters: Infrastructure-specific, implement core contracts
- Applications: Business workflows, orchestrate adapters

## Integration Patterns

### IOTA Blockchain Integration
```rust
// 1. Explicit AWS KMS storage adapter
let storage = StorageBuilder::new()
    .aws_kms()
    .build_aws_kms()
    .await?;

// 2. Generate dynamic KMS key with alias
let alias = format!("aws-kms-demo-{}", timestamp);
let (key_id, public_key_der) = storage
    .generate_key_with_options(AwsKmsKeyOptions::new(alias))
    .await?;

// 3. Derive IOTA address from DER public key
let iota_address = derive_iota_address_from_der(&public_key_der)?;

// 4. Sign IOTA transaction with canonicalization
let signer = storage.get_signer(&key_id)?;
let signature = signer.sign(&transaction_hash).await?;
```

### Multi-Chain Support
The same key can be used across different blockchains:
- **IOTA**: secp256r1 signatures
- **Ethereum**: secp256k1 signatures (via adapter translation)
- **Bitcoin**: secp256k1 with specific encoding

### Enterprise Integration
```rust
// AWS KMS for production with compliance
let storage = StorageBuilder::new()
    .aws_kms()
    .with_region("eu-west-1".to_string())
    .with_environment(Environment::Production)
    .build_aws_kms()
    .await?;

// Supports both authentication methods:
// 1. AWS_PROFILE=production-profile (recommended)
// 2. AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY
```

## Authentication Methods

The Storage Factory supports flexible AWS authentication:

```rust
// Profile-based (if AWS_PROFILE is set)
let storage_with_profile = StorageBuilder::new()
    .aws_kms()
    .build_aws_kms()  // Uses AWS profile authentication
    .await?;

// Direct credentials (if AWS_PROFILE not set)
let storage_with_keys = StorageBuilder::new()
    .aws_kms()
    .build_aws_kms()  // Uses AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY
    .await?;
```

## Complete IOTA Workflow Example

```bash
# Set authentication (choose one method)
export AWS_PROFILE=your-profile-name
export AWS_REGION=eu-west-1

# OR direct credentials
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_REGION=eu-west-1

# Run complete IOTA demo
cargo run --package storage-factory --example iota_kms_demo
```