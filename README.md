# CloudAudit

Lightweight multi-cloud security auditing tool using AWS CLI (zero dependencies).

## Overview

CloudAudit is a security auditing tool designed to run in AWS CloudShell where pip installations are not possible due to the 1GB storage limit. It uses AWS CLI instead of boto3 for all API calls, making it completely dependency-free.

## Features

- **Zero Dependencies** - Uses only AWS CLI, works directly in CloudShell
- **Multi-Cloud Ready** - Architecture supports AWS, Azure, and GCP
- **Prowler-Compatible** - Check structure matches Prowler for easy migration
- **Compliance Mapping** - CIS AWS Foundations Benchmark included

## Installation

```bash
# Clone in CloudShell
git clone https://github.com/YOUR_USERNAME/cloudaudit.git
cd cloudaudit
```

## Usage

```bash
# Run all AWS checks
python3 cloudaudit.py -p aws

# Run specific service
python3 cloudaudit.py -p aws -s s3

# Run specific check
python3 cloudaudit.py -p aws -c s3_bucket_public_access

# Output to JSON
python3 cloudaudit.py -p aws -o json --output-file audit.json

# Output to HTML
python3 cloudaudit.py -p aws -o html --output-file audit.html

# List available checks
python3 cloudaudit.py --list-checks
```

## Available Checks

| Check ID | Service | Severity | Description |
|---------|---------|----------|------------|
| s3_bucket_public_access | S3 | CRITICAL | Ensure S3 buckets do not allow public access |
| s3_bucket_server_side_encryption | S3 | HIGH | Ensure S3 buckets have encryption at rest enabled |
| s3_bucket_versioning_enabled | S3 | MEDIUM | Ensure S3 bucket versioning is enabled |
| s3_bucket_logging_enabled | S3 | MEDIUM | Ensure S3 buckets have logging enabled |
| iam_root_mfa_enabled | IAM | CRITICAL | Ensure MFA is enabled for the root user |
| iam_password_policy | IAM | HIGH | Ensure IAM password policy exists |
| iam_users_without_mfa | IAM | CRITICAL | Ensure IAM users have MFA enabled |
| iam_admin_roles | IAM | CRITICAL | Ensure IAM admin roles do not have direct users |
| ec2_security_groups_opens_ssh | EC2 | HIGH | Ensure security groups do not allow SSH from 0.0.0.0/0 |
| ec2_public_ips | EC2 | MEDIUM | Ensure EC2 instances do not have public IPs |

## Client Setup

### 1. Create Audit User

Ask your client to create an IAM user with read-only access for auditing:

1. Go to IAM > Users > Add user
2. Set user name: `cloudaudit-audit`
3. Access type: Programmatic access
4. Attach policy: Use `compliance/aws/audit_user_policy.json`

### 2. Run Audit

```bash
# Configure AWS credentials
aws configure

# Run audit
python3 cloudaudit.py -p aws -o json --output-file audit.json
```

## Development

### Adding New Checks

1. Create check directory:
```bash
mkdir -p providers/aws/services/s3/s3_new_check
```

2. Create check file:
```python
# providers/aws/services/s3/s3_new_check/s3_new_check.py
from lib.check.models import Check, Check_Report_AWS
from providers.aws.services.s3.s3_client import get_s3_client

class s3_new_check(Check):
    def __init__(self):
        super().__init__()
        self.service_name = "s3"
        self._metadata.CheckID = "s3_new_check"
        # ... set metadata
    
    def execute(self):
        findings = []
        client = get_s3_client()
        for bucket in client.buckets:
            # check logic
            findings.append(report)
        return findings
```

3. Add metadata file:
```json
# s3_new_check.metadata.json
{
  "Provider": "aws",
  "CheckID": "s3_new_check",
  "CheckTitle": "...",
  ...
}
```

## License

Apache License 2.0