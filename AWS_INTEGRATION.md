# 🔐 IOTA Secret Storage - AWS KMS Setup

Quick setup guide for AWS KMS with profile and assume role configuration.

## 🚀 Quick Start

### 1. Environment Configuration
```bash
# Copy the example environment file
cp .env.example .env
```

### 2. AWS Profile Setup

Create `~/.aws/config`:
```ini
[default]
region = eu-west-1

[profile your-profile-name]
role_arn = arn:aws:iam::YOUR-ACCOUNT-ID:role/YourRole
source_profile = default
region = eu-west-1
```

Create `~/.aws/credentials`:
```ini
[default]
aws_access_key_id = YOUR_ACCESS_KEY
aws_secret_access_key = YOUR_SECRET_KEY
```

### 3. Test Your Setup
```bash
# Test AWS profile works
aws sts get-caller-identity --profile your-profile-name

# Run IOTA examples
AWS_REGION=eu-west-1 cargo run --package storage-factory --example iota_kms_demo
AWS_PROFILE=your-profile-name AWS_REGION=eu-west-1 cargo run --package aws-kms-adapter --example profile_usage
```

## 🎯 Key Features

- ✅ **AWS Profile Authentication** with assume role
- ✅ **IOTA Transaction Signing** with KMS
- ✅ **Enterprise-Ready** authentication patterns
- ✅ **Comprehensive Logging** for all operations
- ✅ **Multiple Authentication Methods** (profiles, direct, containers)

## 📋 Examples Available

| Example | Description | Command |
|---------|-------------|---------|
| **IOTA Transaction Signing** | Full transaction workflow with logging | `cargo run --package storage-factory --example iota_transaction_signing` |
| **Profile Authentication** | AWS profile with assume role | `cargo run --package aws-kms-adapter --example profile_usage` |
| **Enterprise Service** | Container/ECS/EKS patterns | `cargo run --package aws-kms-adapter --example enterprise_service` |
| **Auto Detection** | Automatic adapter selection | `cargo run --package storage-factory --example auto_detect_test` |
| **Key Storage Test** | Basic KMS operations | `cargo run --package aws-kms-adapter --example key_storage_test` |

## 🔧 Configuration Details

### Environment Variables (.env)
```bash
# Primary configuration
AWS_PROFILE=your-profile-name
AWS_REGION=eu-west-1

# Optional for specific use cases
# KMS_KEY_ID=arn:aws:kms:eu-west-1:YOUR-ACCOUNT-ID:key/your-key-id
# TARGET_ROLE_ARN=arn:aws:iam::YOUR-ACCOUNT-ID:role/YourRole
```

### Required IAM Permissions
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
            "Resource": "arn:aws:kms:eu-west-1:YOUR-ACCOUNT-ID:key/*"
        }
    ]
}
```

## 🏢 Enterprise Deployment

### Container Environments
For ECS, EKS, or EC2, only set:
```bash
AWS_REGION=eu-west-1
# No credentials needed - use IAM roles
```

### Cross-Account Access
```bash
TARGET_ROLE_ARN=arn:aws:iam::304431203043:role/DeveloperFullAccessRole
SERVICE_NAME=iota-secret-storage
```

## 📊 Logging Output Example

```
[1757077118379] 🚀 IOTA Transaction Signing Service - Session: IOTA_SESSION_1757077118379
[1757077118511] 📝 LOG: Transaction data to sign:
[1757077118511] 📝   - Transaction Type: IOTA Transfer  
[1757077118511] 📝   - Data Size: 64 bytes
[1757077118511] ✅ LOG: IOTA transaction signed successfully!
[1757077118511] 📊 LOG: Signature metrics:
[1757077118511] 📊   - Signature Size: 64 bytes
[1757077118511] 📊   - Algorithm: ECDSA_SHA256
```

## 🛠️ Troubleshooting

### Common Issues

1. **"No credentials found"**
   ```bash
   # Check your AWS credentials
   aws configure list --profile developer
   ```

2. **"Unable to assume role"**
   ```bash
   # Test role assumption directly
   aws sts get-caller-identity --profile developer
   ```

3. **"KMS access denied"**
   - Check IAM policy on the role
   - Verify KMS key policy allows the role

### Debug Commands
```bash
# Check AWS configuration
aws configure list --profile developer

# Test KMS access
aws kms list-keys --region eu-west-1 --profile developer

# Run with debug logging
RUST_LOG=debug cargo run --package storage-factory --example iota_transaction_signing
```

## 📚 Documentation

- [Full AWS Setup Guide](doc/aws-setup.md)
- [Architecture Documentation](doc/refactor.it.md)
- [Core Traits Documentation](core/secret-storage/README.md)

## 🎉 Ready to Use!

Your IOTA Secret Storage with AWS KMS is ready. Run the examples to see it in action:

```bash
cargo run --package storage-factory --example iota_transaction_signing
```