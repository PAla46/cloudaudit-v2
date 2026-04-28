# CloudAudit Architecture Guide

## Table of Contents
1. [Directory Structure](#directory-structure)
2. [Core Components](#core-components)
3. [How Checks Work](#how-checks-work)
4. [Adding New Checks](#adding-new-checks)
5. [Adding New Services](#adding-new-services)
6. [Adding New Providers](#adding-new-providers)
7. [Compliance Mapping](#compliance-mapping)
8. [Output Formats](#output-formats)

---

## Directory Structure

```
cloudaudit/
├── cloudaudit.py           # Main CLI entry point
├── pyproject.toml         # Package configuration
├── README.md            # Documentation
├── .gitignore          # Git ignore rules
│
├── lib/
│   ├── check/
│   │   └── models.py   # Check, Check_Report, CheckMetadata base classes
│   └── allowlisters/
│       └── __init__.py  # Allowlist functionality (reserved)
│
├── providers/                    # Cloud provider implementations
│   ├── __init__.py
│   ├── azure.py              # Azure provider stub
│   └── aws/
│       ├── aws_provider.py              # AWS CLI wrapper
│       ├── aws_regions_by_service.json   # Region configuration
│       └── services/                # Service clients & checks
│           ├── __init__.py
│           ├── s3/                 # S3 service
│           │   ├── s3_client.py      # S3 data fetcher
│           │   └── s3_*/
│           │       └── check files...
│           ├── iam/                 # IAM service
│           │   ├── iam_client.py
│           │   └── iam_*/
│           ├── ec2/
│           │   ├── ec2_client.py
│           │   └── ec2_*/
│           ├── cloudtrail/
│           │   └── cloudtrail_client.py
│           └── rds/
│               └── rds_client.py
│
├── output/
│   ├── json.py           # Output formatters (JSON, CSV, HTML)
│   └── ...
│
└── compliance/
    └── aws/
        ├── cis_aws.json           # CIS compliance mapping
        └── audit_user_policy.json  # IAM policy for audit user
```

---

## Core Components

### 1. cloudaudit.py (Main CLI)
**Purpose:** Entry point, argument parsing, orchestrates checks

**Key Functions:**
- `parse_args()` - CLI argument parsing
- `main()` - Main execution flow
- `_load_aws_checks()` - Imports and instantiates all checks
- `CloudAudit.run()` - Executes all checks

**To add new checks:** Modify `_load_aws_checks()` function

---

### 2. providers/aws/aws_provider.py
**Purpose:** AWS CLI wrapper for making API calls

**Key Classes:**
- `AWSCLI` - Low-level CLI command execution
- `AWSProvider` - High-level AWS API methods

**Key Methods:**
```python
# List resources
list_buckets()
list_users()
list_security_groups()
describe_instances()
describe_db_instances()
list_trails()
list_functions()

# Get specific resources
get_bucket_policy(bucket_name)
get_bucket_acl(bucket_name)
get_bucket_encryption(bucket_name)
```

**To add new API calls:** Add methods to `AWSProvider` class

---

### 3. lib/check/models.py
**Purpose:** Base classes for checks and findings

**Key Classes:**
```python
class Check(ABC)          # Base check class
class CheckMetadata     # Metadata (check info)
class Check_Report    # Generic finding
class Check_Report_AWS(AWS-specific finding)
```

---

## How Checks Work

### Check Structure
Each check is a Python class that:
1. Inherits from `Check` base class
2. Implements `execute()` method
3. Returns list of `Check_Report_AWS` findings

### Check File Location
```
providers/aws/services/{service}/{check_name}/
├── __init__.py                    # Empty placeholder
├── {check_name}.py               # Check implementation
└── {check_name}.metadata.json    # Metadata (optional)
```

### Check Implementation Template
```python
from lib.check.models import Check, Check_Report_AWS
from providers.aws.services.{service}.{service}_client import get_{service}_client

class {check_name}(Check):
    def __init__(self):
        super().__init__()
        self.service_name = "{service}"
        
        # Set metadata
        self._metadata.CheckID = "{check_name}"
        self._metadata.CheckTitle = "..."
        self._metadata.ServiceName = "{service}"
        self._metadata.Severity = "critical|high|medium|low"
        self._metadata.Categories = ["...]
        self._metadata.ResourceType = "Aws{Service}{ResourceType}"
        self._metadata.ResourceGroup = "..."
        self._metadata.Description = "..."
        self._metadata.Risk = "..."
        self._metadata.Remediation = {...}
    
    def execute(self):
        findings = []
        client = get_{service}_client()
        
        # Iterate over resources
        for resource in client.{resources}:
            report = Check_Report_AWS(
                check_id=self.CheckID,
                check_metadata=self._metadata,
                resource=resource
            )
            
            # Determine status
            report.status = "PASS" if condition else "FAIL"
            report.status_extended = "..."
            
            # Resource info
            report.region = resource.region
            report.resource_id = resource.id
            report.resource_arn = resource.arn
            
            findings.append(report)
        
        return findings

# Create instance
{check_name}_instance = {check_name}()
```

### Metadata File Format
```json
{
  "Provider": "aws",
  "CheckID": "check_name",
  "CheckTitle": "Descriptive title",
  "CheckType": ["Software and Configuration Checks/..."],
  "ServiceName": "service",
  "Severity": "critical|high|medium|low",
  "ResourceType": "AwsServiceResource",
  "ResourceGroup": "storage|IAM|compute|...",
  "Description": "What the check does",
  "Risk": "Why it matters",
  "Categories": ["category"],
  "Remediation": {
    "Code": {"CLI": "aws command..."},
    "Recommendation": {"Text": "...", "Url": "..."}
  }
}
```

---

## Adding New Checks

### Step 1: Create Check Directory
```bash
mkdir -p providers/aws/services/{service}/check_{name}
```

### Step 2: Create Check File
```python
# providers/aws/services/{service}/check_{name}/check_{name}.py

from lib.check.models import Check, Check_Report_AWS
from providers.aws.services.{service}.{service}_client import get_{service}_client

class check_name(Check):
    def __init__(self):
        super().__init__()
        self.service_name = "{service}"
        self._metadata.CheckID = "check_name"
        self._metadata.CheckTitle = "Ensure ..."
        self._metadata.ServiceName = "{service}"
        self._metadata.Severity = "high"
        self._metadata.ResourceType = "AwsServiceResource"
        self._metadata.ResourceGroup = "..."
        self._metadata.Description = "..."
        self._metadata.Risk = "..."
        self._metadata.Categories = ["..."]
        self._metadata.Remediation = {
            "Code": {"CLI": "..."},
            "Recommendation": {"Url": "..."}
        }
    
    def execute(self):
        findings = []
        client = get_{service}_client()
        
        for resource in client.resources:
            report = Check_Report_AWS(
                check_id=self.CheckID,
                check_metadata=self._metadata,
                resource=resource
            )
            report.status = "PASS" if not issue else "FAIL"
            report.status_extended = "..."
            report.region = resource.region
            report.resource_id = resource.name
            report.resource_arn = f"arn:aws:{service}::...{resource.name}"
            findings.append(report)
        
        return findings

check_name_instance = check_name()
```

### Step 3: Create Metadata (Optional)
```json
{
  "Provider": "aws",
  "CheckID": "check_name",
  "CheckTitle": "...",
  "ServiceName": "{service}",
  "Severity": "high",
  ...
}
```

### Step 4: Create __init__.py
```bash
touch providers/aws/services/{service}/check_{name}/__init__.py
```

### Step 5: Register Check
Edit `cloudaudit.py` -> `_load_aws_checks()`:
```python
from providers.aws.services.{service}.check_{name}.check_{name} import check_name

return [
    # ... existing checks ...
    check_name(),
]
```

---

## Adding New Services

### Step 1: Create Service Client
```python
# providers/aws/services/{service}/{service}_client.py

import json
from dataclasses import dataclass, field
from typing import List

from providers.aws.aws_provider import AWSProvider

@dataclass
class ServiceResource:
    # Define resource attributes
    id: str
    name: str
    region: str = "us-east-1"
    # Add more attributes...

class ServiceClient:
    def __init__(self, provider: AWSProvider):
        self.provider = provider
        self.resources: List[ServiceResource] = []
        self.region = provider.region
        self.__scan()
    
    def __scan(self):
        # Fetch resources from AWS
        data = self.provider.list_{resources}()
        for item in data:
            resource = ServiceResource(
                id=item.get("Id"),
                name=item.get("Name"),
                region=self.region
            )
            self.resources.append(resource)

# Singleton pattern
{service}_client = None

def get_{service}_client(provider=None):
    global {service}_client
    if {service}_client is None:
        if provider is None:
            provider = AWSProvider()
        {service}_client = ServiceClient(provider)
    return {service}_client
```

### Step 2: Add API Methods
Edit `providers/aws/aws_provider.py`:
```python
def list_{resources}(self):
    return self.cli.run_paginated([
        "aws", "{service}", "list-{resources}",
        "--output", "json"
    ])
```

### Step 3: Add to Regions Config
Edit `providers/aws/aws_regions_by_service.json`:
- Add service to `regional_services` or `global_services`

---

## Adding New Providers (Azure, GCP)

### Step 1: Create Provider File
```python
# providers/azure.py

class AzureProvider:
    def __init__(self):
        self.cli = AzureCLI()
    
    def list_resources(self):
        # Use Azure CLI
        pass
```

### Step 2: Create Service Client
```python
# providers/azure/services/{service}/{service}_client.py
# Similar pattern to AWS
```

### Step 3: Add Checks
```python
# providers/azure/services/{service}/check_{name}/check_{name}.py

from lib.check.models import Check, Check_Report

class check_name(Check):
    def __init__(self):
        super().__init__()
        self.service_name = "{service}"
        self._metadata.CheckID = "azure_check_name"
        self._metadata.Provider = "azure"
        # ...
    
    def execute(self):
        # Use Azure provider
        pass
```

### Step 4: Register in CLI
Edit `cloudaudit.py`:
```python
if self.provider_name == "azure":
    check_classes = self._load_azure_checks()
```

---

## Compliance Mapping

### File Location
```
compliance/aws/cis_aws.json
```

### Format
```json
{
  "Framework": "CIS",
  "Name": "CIS AWS Foundations Benchmark",
  "Version": "3.0",
  "Provider": "AWS",
  "Description": "...",
  "Requirements": [
    {
      "Id": "1.1",
      "Description": "Control description",
      "Checks": ["check_id_1", "check_id_2"],
      "Attributes": {
        "Section": "1 Identity and Access Management",
        "Profile": "Level 1",
        "AssessmentStatus": "Automated",
        "Description": "...",
        "RationaleStatement": "...",
        "RemediationProcedure": "...",
        "AuditProcedure": "..."
      }
    }
  ]
}
```

---

## Output Formats

### CSV Columns (Prowler-compatible)
- Uses semicolon `;` delimiter
- 36 columns including AUTH_METHOD, TIMESTAMP, ACCOUNT_UID, CHECK_ID, STATUS, SEVERITY, etc.

### HTML
- Bootstrap 4 styled
- DataTables for sorting/filtering
- Summary cards

### JSON
- Standard JSON with findings array

---

## Common Tasks

### Run Single Check
```bash
python cloudaudit.py -p aws -c check_id
```

### Run Single Service
```bash
python cloudaudit.py -p aws -s s3
```

### Filter by Severity
```bash
python cloudaudit.py -p aws --severity critical
```

### Custom Output File
```bash
python cloudaudit.py -p aws -o json --output-file custom.json
```

---

## Best Practices

1. **Metadata First** - Create metadata file, then implementation
2. **Use Getter Functions** - Don't import singletons directly
3. **Error Handling** - Wrap AWS calls in try/except
4. **Consistent Naming** - Follow `{service}_{check_name}` pattern
5. **Severity Levels** - critical > high > medium > low
6. **Categories** - Use predefined: internet-exposed, encryption, logging, etc.

---

## Copying from Prowler

To copy a check from Prowler:

1. **Copy directory structure** - `prowler/providers/aws/services/{service}/{check_name}/`
2. **Update imports:**
   ```python
   # Before (Prowler):
   from prowler.lib.check.models import Check
   from prowler.providers.aws.services.s3.s3_client import s3_client
   
   # After (Cloudaudit):
   from lib.check.models import Check, Check_Report_AWS
   from providers.aws.services.s3.s3_client import get_s3_client
   ```
3. **Switch client access:** Use `get_s3_client()` instead of `s3_client`
4. **Register in cloudaudit.py**