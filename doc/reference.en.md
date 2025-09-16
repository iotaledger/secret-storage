# IOTA Secret Storage - Enterprise Reference Architecture

## Executive Summary

This document presents a comprehensive reference architecture for enterprise key management integrations with IOTA's Trust Framework. The architecture introduces a modular secret-storage layer that enables organizations to implement flexible, secure, and scalable cryptographic key management solutions while maintaining compatibility with IOTA Identity and notarization capabilities.

The proposed solution addresses enterprise requirements through concrete implementations supporting multiple key management strategies: client-side self-custody with passkey, cloud-based key management services, and third-party specialized services.

## 1. Architecture Overview

### 1.1 Multi-Layer Trust Model

The reference architecture implements a three-tier approach to key management, allowing organizations to choose the appropriate security and trust model for different use cases:

- **Edge/Client Layer**: Self-custody solutions using local enclaves, passkeys, and device-based storage
- **Organizational Layer**: Centralized key management using cloud HSMs and enterprise KMS solutions  
- **Distributed Consensus Layer**: Multi-party computation (MPC) and threshold signatures for critical operations

### 1.2 Design Principles

- **Modularity**: Pluggable key storage implementations through standardized trait interfaces
- **Security by Design**: Enclave-first approach where private keys never leave secure environments
- **Compliance Ready**: Built-in audit trails, access controls, and regulatory compliance support
- **Reusability**: Common interfaces enable rapid deployment across different organizational needs
- **Interoperability**: Native WASM bindings enable web and mobile integrations

## 2. Secret Storage Layer Architecture

### 2.1 Core Trait System

The secret-storage layer provides standardized interfaces implemented in Rust with WASM bindings:

```rust
// Core storage traits for maximum modularity
pub trait KeysStorage<K: SignatureScheme, I>: 
    KeyGenerate<K, I> + KeySign<K, I> + KeyDelete<I> + KeyExist<I> {}

pub trait KeyGenerate<K: SignatureScheme, I> {
    async fn generate_key_with_options(&self, options: Self::Options) -> Result<(I, K::PublicKey)>;
}

pub trait KeySign<K: SignatureScheme, I> {
    fn get_signer(&self, key_id: &I) -> Result<impl Signer<K, KeyId = I>>;
}

pub trait Signer<K: SignatureScheme> {
    async fn sign(&self, data: &K::Input) -> Result<K::Signature>;
    async fn public_key(&self) -> Result<K::PublicKey>;
    fn key_id(&self) -> Self::KeyId;
}
```

### 2.2 Hexagonal Architecture Implementation

The implementation follows hexagonal architecture principles, separating the core domain logic from infrastructure concerns:

- **Core Domain**: Contains only business logic and port definitions (traits)
- **Adapters**: Implement specific technology integrations while conforming to core interfaces
- **Applications**: Orchestrate use cases through port abstractions without infrastructure dependencies

### 2.3 Project Structure

The complete ecosystem is organized following hexagonal architecture patterns:

```
secret-storage-ecosystem/
├── core/                            # Core domain (implemented)
│   ├── src/
│   └── Cargo.toml
│
├── adapters/                        # Infrastructure adapters
│   ├── aws-kms-adapter/                # AWS KMS implementation (implemented)
│   │   ├── src/
│   │   │   ├── config.rs
│   │   │   ├── storage.rs
│   │   │   ├── signer.rs
│   │   │   ├── error.rs
│   │   │   └── utils/               # Modular utilities
│   │   │       ├── aws_client.rs
│   │   │       ├── key_utils.rs
│   │   │       └── kms_operations.rs
│   │   ├── Cargo.toml
│   │   └── examples/
│   │       ├── key_deletion_demo.rs
│   │       ├── secp256r1_demo.rs
│   │       └── signing_demo.rs
│   │
│   ├── filesystem-adapter/          # Local file storage (planned)
│   │   ├── src/
│   │   ├── Cargo.toml
│   │   └── examples/
│   │       └── dev_setup.rs
│   │
│   ├── passkey-adapter/             # WebAuthn/FIDO2 integration (planned)
│   │   ├── src/
│   │   │   └── config.rs
│   │   ├── Cargo.toml
│   │   ├── pkg/                     # WASM output
│   │   └── examples/
│   │       ├── web_demo.html
│   │       └── mobile_integration.rs
│   │
│   └── dfns-adapter/                # MPC service integration (planned)
│       ├── src/
│       ├── Cargo.toml
│       └── examples/
│           └── enterprise_setup.rs
│
├── applications/                    # Application layer
│   └──  storage-factory/             # Factory pattern implementation (implemented)
│       ├── src/
│       │   ├── lib.rs
│       │   ├── builder.rs           # Builder pattern for adapter selection
│       │   └── error.rs             # Application error types
│       ├── examples/
│       │   ├── iota_kms_demo.rs     # Complete IOTA workflow
│       │   ├── iota_address_faucet_demo.rs
│       │   └── utils/               # Shared utilities
│       │       ├── crypto.rs        # IOTA crypto operations
│       │       ├── faucet.rs        # Auto-faucet functionality
│       │       ├── iota_client.rs   # IOTA CLI integration
│       │       └── key_generation.rs
│       └── Cargo.toml
│  
│
└──bindings/                        # Language bindings
    └── wasm/

```

### 2.4 Implementation Strategy

Each concrete adapter focuses on specific enterprise requirements while maintaining interface compatibility:

- **Atomic permissions**: Following the principle of least privilege
- **Explicit boundaries**: Clear separation between provider and user code
- **Enclave assumptions**: Private keys remain within secure execution environments
- **Dependency inversion**: Core domain depends only on abstractions, never on concrete implementations

## 3. Concrete Integrations

### 3.1 AWS KMS Integration

**Use Case**: Enterprise-grade key management with hardware security modules and centralized governance.

**Implementation Features**:
- Minimal environment variable configuration (AWS credentials, region, key policies)
- Native integration with AWS IAM for fine-grained access control
- Support for key rotation, audit logging via CloudTrail
- High availability with 99.9% SLA
- FIPS 140-2 Level 3 HSM protection

**Configuration**:
```rust
pub struct AwsKmsStorage {
    kms_client: aws_sdk_kms::Client,
    key_spec: KeySpec, // secp256r1 (P-256) for IOTA compatibility
    region: String,
}

// Minimal environment variables required:
// AWS_ACCESS_KEY_ID
// AWS_SECRET_ACCESS_KEY  
// AWS_REGION
// KMS_KEY_ID (optional, for existing keys)
```

**Optimal Scenarios**:
- Certificate authorities issuing Verifiable Credentials
- Enterprise audit and compliance logging systems
- Supply chain consortium networks requiring validated signatures

### 3.2 Default IOTA Key Tool Storage

**Use Case**: Development, testing, and low-security environments requiring local file system storage.

**Implementation Features**:
- Unencrypted local storage for development ease
- File-system based key persistence
- Compatible with existing IOTA toolchain
- Zero external dependencies

**Configuration**:
```rust
pub struct FileSystemStorage {
    storage_path: PathBuf,
    key_format: KeyFormat, // JSON, PEM, or binary
}

// Configuration:
// STORAGE_PATH (default: ~/.iota/keys)
// KEY_FORMAT (default: JSON)
```

**Optimal Scenarios**:
- Development and testing environments
- Proof-of-concept implementations  
- Educational and demonstration purposes
- Local development toolchain integration

### 3.3 Passkey Integration

**Use Case**: Client-side self-custody with modern authentication standards, maximizing user experience while maintaining security.

**Implementation Features**:
- FIDO2/WebAuthn compliant authentication
- Platform authenticator integration (TouchID, FaceID, Windows Hello)
- Hardware security module utilization on supported devices
- Cross-platform compatibility via WASM bindings

**Configuration**:
```rust
pub struct PasskeyStorage {
    relying_party: RelyingParty,
    authenticator_attachment: AuthenticatorAttachment, // Platform or Cross-platform
    user_verification: UserVerificationRequirement,
}

// Minimal configuration:
// RP_ID: Relying party identifier
// RP_NAME: Human-readable service name
// USER_ID: Unique user identifier
```

**Optimal Scenarios**:
- Personal digital identity wallets
- Consumer-facing applications requiring self-sovereign identity
- Mobile and web applications with biometric authentication
- Passwordless enterprise user onboarding

### 3.4 Third-Party Service Integration (DFNS Example)

**Use Case**: Professional key management with multi-party computation, advanced policy engines, and institutional-grade security.

**Implementation Features**:
- Multi-party computation (MPC) for distributed key generation and signing
- Threshold signatures requiring multiple approvals
- Advanced policy engine with custom business rules
- API-first integration with webhook support
- Multi-blockchain support in single platform

**Configuration**:
```rust
pub struct DfnsStorage {
    api_client: DfnsApiClient,
    wallet_id: String,
    policy_engine: PolicyEngine,
    mpc_config: MpcConfiguration,
}

// Configuration:
// DFNS_API_KEY: Service authentication
// DFNS_APP_ID: Application identifier  
// DFNS_PRIVATE_KEY: Client-side MPC shard
// WALLET_ID: Target wallet for operations
// POLICY_RULES: JSON configuration for approval workflows
```

**Optimal Scenarios**:
- Multi-signature corporate governance
- High-value transaction approval workflows
- Regulated financial services requiring multiple approvals
- Cross-blockchain enterprise applications

## 4. Client Solution Spectrum

### 4.1 Client-Side Self-Custody Signing

**Architecture**: Direct key management on user devices using passkey integration.

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   User Device   │────│  Passkey Auth    │────│  IOTA     │
│  (TouchID/Face) │    │   (Local Sign)   │    │  (Verification) │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

**Benefits**:
- Complete user autonomy over digital identity
- Zero dependency on external services
- Maximum privacy preservation
- Offline capability for signing operations

**Implementation**:
- WASM-compiled secret-storage with passkey backend
- Local key generation within secure enclave
- Direct transaction signing and DID operations
- Browser/mobile app integration via WebAuthn

### 4.2 Backend-Side Key Management and Signing

**Architecture**: Centralized enterprise key management with multiple backend options.

```
┌──────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Client Request  │────│  Backend API    │────│  Key Management │
│  (Authenticated) │    │  (Policy Check) │    │  (AWS KMS/DFNS) │
└──────────────────┘    └─────────────────┘    └─────────────────┘
                                │
                                ▼
                        ┌─────────────────┐
                        │  IOTA     │
                        │  (Notarization) │
                        └─────────────────┘
```

**Options**:

**a) Key Tool Storage**:
- Simple file-system storage for development
- Quick setup and deployment
- Suitable for controlled environments

**b) AWS KMS**:
- Enterprise-grade HSM security
- Centralized key governance and audit
- Integrated with existing AWS infrastructure

**c) Third-Party Services (DFNS)**:
- Advanced MPC-based security
- Multi-approval workflows
- Professional key custody services

## 5. Implementation Roadmap

### 5.1 Phase 1: Core Infrastructure ✅
- [x] Implement trait-based storage layer in Rust
- [x] Develop AWS KMS concrete implementation with secp256r1 support
- [x] Build storage factory with builder pattern
- [x] Create comprehensive examples and documentation
- [ ] Create WASM bindings for web integration (planned)
- [ ] Build file system storage for development (planned)

### 5.2 Phase 2: Advanced Integrations 🚧 
- [ ] Implement passkey storage with WebAuthn (planned)
- [ ] Integrate DFNS or similar MPC service (planned)
- [ ] Create policy engine for enterprise governance (planned)
- [ ] Develop monitoring and audit capabilities (planned)
- [x] Complete IOTA blockchain integration with transaction workflow
- [x] Implement signature canonicalization for ECDSA compliance

### 5.3 Phase 3: Enterprise Features 📋
- [ ] Advanced key rotation mechanisms
- [ ] Compliance reporting tools
- [x] Modular utilities architecture for maintainable code

## 6. Integration Benefits

### 6.1 For IOTA Ecosystem
- **Accelerated Adoption**: Lower barriers to enterprise integration
- **Security Standardization**: Consistent key management across implementations
- **Compliance Enablement**: Built-in support for regulatory requirements
- **Scalability**: Support for high-volume enterprise deployments

### 6.2 For Enterprise Clients
- **Flexible Deployment**: Choose appropriate security model per use case
- **Risk Management**: Multi-layered security approach
- **Operational Efficiency**: Standardized interfaces across different backends
- **Future-Proofing**: Modular design enables easy migration between solutions

### 6.3 For Developers
- **Rapid Integration**: Pre-built connectors for common platforms
- **Consistent APIs**: Single interface across different key management systems
- **WASM Compatibility**: Universal deployment across web, mobile, and server environments
- **Type Safety**: Rust-based implementation with compile-time guarantees

## 7. Security Considerations

### 7.1 Threat Model
- **Key Extraction**: Private keys never leave secure environments
- **Insider Threats**: Multi-party approval for sensitive operations
- **Network Attacks**: All communications encrypted and authenticated
- **Physical Compromise**: Hardware security module integration where available

### 7.2 Compliance Framework
- **SOC 2 Type II**: Audit trail and access control requirements
- **ISO 27001**: Information security management standards  
- **GDPR**: Privacy-by-design for personal data handling
- **Industry Specific**: Financial services, healthcare, and government requirements

## 8. Conclusion

This reference architecture provides enterprises with a clear path to integrate secure, scalable key management solutions with IOTA's Trust Framework. By offering multiple concrete implementations ranging from simple file-based storage to advanced MPC services, organizations can choose the appropriate security and operational model for their specific requirements.

The modular design ensures that implementations remain interoperable while allowing for future expansion and technology evolution. With native WASM support and Rust's security guarantees, the solution provides both performance and safety for enterprise-grade deployments.

Through this architecture, IOTA can offer clients a comprehensive range of solutions: from self-sovereign identity applications using client-side passkeys to enterprise-grade key management using cloud HSMs and professional custody services. This flexibility positions IOTA as a versatile platform capable of meeting diverse organizational security and compliance requirements.