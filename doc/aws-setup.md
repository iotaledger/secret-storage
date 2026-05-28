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
aws sts get-caller-identity --profile developer

```

## Configuration Explained

### AWS Profile with AssumeRole Setup

#### Step 1: Create Base IAM User
First, create an IAM user that will serve as the "source" for role assumption:

1. **Create IAM User** (e.g., `iota-base-user`)
2. **Generate Access Keys** for this user
3. **Attach minimal policy** allowing only role assumption:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Resource": "arn:aws:iam::YOUR-ACCOUNT-ID:role/DeveloperFullAccessRole"
        }
    ]
}
```

#### Step 2: Create Target IAM Role
Create the role that will have actual KMS permissions:

1. **Create IAM Role** (e.g., `DeveloperFullAccessRole`)
2. **Attach KMS policy** (see IAM Policy Requirements section below)
3. **Configure trust policy** to allow your base user to assume it:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::YOUR-ACCOUNT-ID:user/iota-base-user"
            },
            "Action": "sts:AssumeRole",
            "Condition": {
                "StringEquals": {
                    "sts:ExternalId": "optional-external-id"
                }
            }
        }
    ]
}
```

#### Step 3: Configure AWS Files

**~/.aws/credentials** (contains base user credentials):
```ini
[default]
aws_access_key_id = AKIA... # Base user access key
aws_secret_access_key = ... # Base user secret key
```

**~/.aws/config** (defines profile with role assumption):
```ini
[default]
region = eu-west-1

[profile developer]
role_arn = arn:aws:iam::YOUR-ACCOUNT-ID:role/DeveloperFullAccessRole
source_profile = default
region = eu-west-1
# external_id = optional-external-id  # If used in trust policy
# duration_seconds = 3600             # Optional: session duration
# role_session_name = iota-session     # Optional: custom session name
```

### AWS Profile Flow
1. **Base Credentials**: Stored in `[default]` profile in `~/.aws/credentials`
2. **Role Assumption**: `developer` profile uses `default` credentials to assume `DeveloperFullAccessRole`
3. **Temporary Credentials**: AWS SDK automatically gets temporary credentials with role permissions
4. **IOTA Integration**: Application uses the `developer` profile for all KMS operations

### Environment Variables
- `AWS_PROFILE=developer`: Tells AWS SDK to use the specified profile with role assumption
- `AWS_REGION=eu-west-1`: Specifies the AWS region for KMS operations

## Alternative Configurations

### Cross-Account Role Assumption
For accessing KMS keys in different AWS accounts:

```bash
# In .env file:
TARGET_ROLE_ARN=arn:aws:iam::CROSS-ACCOUNT-ID:role/CrossAccountKMSRole
SERVICE_NAME=iota-secret-storage-service
AWS_REGION=eu-west-1

# The cross-account role must trust your base account and have KMS permissions
```

### Multiple Profiles for Different Environments
You can configure multiple profiles for different environments:

**~/.aws/config**:
```ini
[profile dev]
role_arn = arn:aws:iam::DEV-ACCOUNT-ID:role/DeveloperRole
source_profile = default
region = eu-west-1

[profile staging]
role_arn = arn:aws:iam::STAGING-ACCOUNT-ID:role/StagingRole
source_profile = default
region = eu-west-1

[profile prod]
role_arn = arn:aws:iam::PROD-ACCOUNT-ID:role/ProductionRole
source_profile = default
region = eu-west-1
mfa_serial = arn:aws:iam::BASE-ACCOUNT-ID:mfa/your-username
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
# AWS KMS key deletion demonstration
AWS_PROFILE=developer cargo run --package aws-kms-adapter --example key_deletion_demo

# secp256r1 signature demonstration
AWS_PROFILE=developer cargo run --package aws-kms-adapter --example secp256r1_demo

# Basic signing operations
AWS_PROFILE=developer cargo run --package aws-kms-adapter --example signing_demo
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