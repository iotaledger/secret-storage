# AWS KMS Setup

## Authentication

The adapter reads two environment variables:

- `AWS_REGION` (required) — the AWS region to use
- `AWS_PROFILE` (optional) — if set, the adapter uses `AwsKmsStorage::from_profile()`; otherwise it falls back to `AwsKmsStorage::from_env()`, which uses the AWS SDK's standard credential chain (instance profile, `~/.aws/credentials`, etc.)

### Profile with AssumeRole

Create or update `~/.aws/credentials`:

```ini
[default]
aws_access_key_id = AKIA...
aws_secret_access_key = ...
```

Create or update `~/.aws/config`:

```ini
[default]
region = eu-west-1

[profile developer]
role_arn = arn:aws:iam::YOUR-ACCOUNT-ID:role/YourRole
source_profile = default
region = eu-west-1
```

## Required IAM Permissions

Attach this policy to your role:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "kms:DescribeKey",
                "kms:GetPublicKey",
                "kms:Sign",
                "kms:ScheduleKeyDeletion",
                "kms:CreateAlias",
                "kms:ListAliases",
                "kms:TagResource",
                "kms:UntagResource",
                "kms:ListResourceTags"
            ],
            "Resource": "arn:aws:kms:REGION:YOUR-ACCOUNT-ID:key/*"
        },
        {
            "Effect": "Allow",
            "Action": ["kms:CreateAlias"],
            "Resource": "arn:aws:kms:REGION:YOUR-ACCOUNT-ID:alias/*"
        },
        {
            "Effect": "Allow",
            "Action": ["kms:CreateKey", "kms:ListKeys", "kms:ListAliases"],
            "Resource": "*"
        }
    ]
}
```

## Verify Setup

Test your identity and KMS access:

```bash
aws sts get-caller-identity --profile developer
aws kms list-keys --region eu-west-1 --profile developer
```

## Run Examples

```bash
AWS_PROFILE=developer cargo run --package aws-kms-adapter --example key_deletion_demo
AWS_PROFILE=developer cargo run --package aws-kms-adapter --example secp256r1_demo
AWS_PROFILE=developer cargo run --package aws-kms-adapter --example signing_demo
```

## Troubleshooting

- **"No credentials found"**: check `~/.aws/credentials` and that `AWS_PROFILE` matches a profile name
- **"Unable to assume role"**: verify the role ARN and that the trust policy allows your user/role
- **"Access denied" for KMS**: verify the IAM policy and the KMS key policy
