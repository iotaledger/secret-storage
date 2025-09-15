# AWS Configuration Setup for IOTA Secret Storage

This document explains how to configure AWS authentication for IOTA Secret Storage using profiles and assume role.

## Quick Setup

### 1. Copy Environment File
```bash
cp .env.example .env
```

### 2. Configure AWS Profiles

Create or update `~/.aws/config`:
```ini
[default]
region = eu-west-1

[profile your-profile-name]
role_arn = arn:aws:iam::YOUR-ACCOUNT-ID:role/YourRole
source_profile = default
region = eu-west-1
```

### 3. Configure AWS Credentials

Create or update `~/.aws/credentials`:
```ini
[default]
aws_access_key_id = YOUR_ACCESS_KEY_HERE
aws_secret_access_key = YOUR_SECRET_ACCESS_KEY_HERE
```

### 4. Test Configuration
```bash
# Test AWS profile
aws sts get-caller-identity --profile your-profile-name

# Run IOTA examples
AWS_REGION=eu-west-1 cargo run --package storage-factory --example iota_kms_demo
AWS_PROFILE=your-profile-name AWS_REGION=eu-west-1 cargo run --package aws-kms-adapter --example profile_usage
```

## Configuration Explained

### AWS Profile Flow
1. **Base Credentials**: Stored in `[default]` profile in `~/.aws/credentials`
2. **Role Assumption**: Your named profile assumes your specified role using base credentials
3. **IOTA Integration**: Application uses your profile for all KMS operations

### Environment Variables
- `AWS_PROFILE=your-profile-name`: Tells AWS SDK to use the specified profile
- `AWS_REGION=eu-west-1`: Specifies the AWS region for KMS operations

## Alternative Configurations

### Direct Role Assumption (without profiles)
```bash
# In .env file:
TARGET_ROLE_ARN=arn:aws:iam::304431203043:role/DeveloperFullAccessRole
SERVICE_NAME=iota-secret-storage-service
AWS_REGION=eu-west-1

# Run with explicit role assumption:
cargo run --package aws-kms-adapter --example enterprise_service -- assume-role
```

### Container Environments
For ECS, EKS, or EC2 with IAM roles, only set:
```bash
AWS_REGION=eu-west-1
```

## IAM Policy Requirements

The `DeveloperFullAccessRole` needs these KMS permissions:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "IOTASecretStorageKMSAccess",
            "Effect": "Allow",
            "Action": [
                "kms:CreateKey",
                "kms:DescribeKey",
                "kms:GetPublicKey",
                "kms:Sign",
                "kms:ScheduleKeyDeletion",
                "kms:ListKeys",
                "kms:CreateAlias",
                "kms:ListAliases",
                "kms:TagResource",
                "kms:UntagResource",
                "kms:ListResourceTags"
            ],
            "Resource": "arn:aws:kms:eu-west-1:304431203043:key/*"
        },
        {
            "Sid": "IOTASecretStorageKMSList",
            "Effect": "Allow",
            "Action": [
                "kms:ListKeys",
                "kms:ListAliases"
            ],
            "Resource": "*"
        }
    ]
}
```

## Testing Your Setup

### 1. AWS CLI Test
```bash
# Test base credentials
aws sts get-caller-identity

# Test profile assume role
aws sts get-caller-identity --profile developer

# Test KMS access
aws kms list-keys --region eu-west-1 --profile developer
```

### 2. IOTA Secret Storage Tests
```bash
# Basic functionality test
cargo run --package aws-kms-adapter --example key_storage_test

# Profile authentication test  
cargo run --package aws-kms-adapter --example profile_usage

# Full IOTA transaction signing test
cargo run --package storage-factory --example iota_transaction_signing

# Auto-detection test
cargo run --package storage-factory --example auto_detect_test
```

## Troubleshooting

### Common Issues

1. **"No credentials found" error**
   - Check `~/.aws/credentials` exists and has correct format
   - Verify `AWS_PROFILE` matches profile name in config

2. **"Unable to assume role" error**
   - Check role ARN is correct: `arn:aws:iam::304431203043:role/DeveloperFullAccessRole`
   - Verify base credentials have permission to assume the role
   - Check role trust policy allows your user/role to assume it

3. **"Access denied" for KMS operations**
   - Verify the assumed role has KMS permissions (see IAM policy above)
   - Check the KMS key policy allows the role to use it

### Debug Commands
```bash
# Check current AWS identity
aws sts get-caller-identity --profile developer

# List available KMS keys
aws kms list-keys --region eu-west-1 --profile developer

# Test role assumption
aws sts assume-role \
    --role-arn arn:aws:iam::304431203043:role/DeveloperFullAccessRole \
    --role-session-name test-session
```

## Production Considerations

1. **Security**: Never commit `.env` file to version control
2. **Rotation**: Regularly rotate access keys in `~/.aws/credentials`
3. **Monitoring**: Enable CloudTrail logging for KMS operations
4. **Least Privilege**: Grant only necessary KMS permissions to the role
5. **Multi-Account**: Consider separate AWS accounts for dev/staging/prod

## Enterprise Deployment

For enterprise environments, consider:
- **ECS/EKS**: Use task roles instead of profiles
- **EC2**: Use instance profiles
- **CI/CD**: Use OIDC federation for GitHub Actions, etc.
- **Cross-Account**: Separate AWS accounts with cross-account roles