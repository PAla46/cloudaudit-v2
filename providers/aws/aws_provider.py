import json
import os
import subprocess
from typing import Any, Optional


AWS_REGIONS_FILE = os.path.join(os.path.dirname(__file__), "aws_regions_by_service.json")

GLOBAL_SERVICES = ["iam", "s3", "cloudtrail", "route53", "cloudfront", "shield", "waf", "fms"]


def get_available_regions():
    if os.path.exists(AWS_REGIONS_FILE):
        with open(AWS_REGIONS_FILE) as f:
            data = json.load(f)
            return data.get("regions", ["us-east-1"])
    return ["us-east-1"]


def is_global_service(service_name):
    if os.path.exists(AWS_REGIONS_FILE):
        with open(AWS_REGIONS_FILE) as f:
            data = json.load(f)
            return service_name.lower() in data.get("global_services", [])
    return service_name.lower() in GLOBAL_SERVICES


class AWSCLIError(Exception):
    pass


class AWSCLI:
    @staticmethod
    def run(command: list, parse_json: bool = True) -> Any:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            error_msg = result.stderr.strip() or result.stdout.strip()
            raise AWSCLIError(f"Command failed: {' '.join(command)}\nError: {error_msg}")
        
        if parse_json:
            try:
                return json.loads(result.stdout) if result.stdout.strip() else []
            except json.JSONDecodeError:
                return result.stdout.strip()
        return result.stdout

    @staticmethod
    def run_paginated(command: list, next_token_key: str = "NextToken") -> list:
        results = []
        next_token = None
        
        while True:
            cmd = command.copy()
            if next_token:
                cmd.extend(["--starting-token", next_token])
            
            output = subprocess.run(cmd, capture_output=True, text=True)
            
            if output.returncode != 0:
                raise AWSCLIError(f"Command failed: {' '.join(cmd)}\n{output.stderr}")
            
            data = json.loads(output.stdout) if output.stdout.strip() else {}
            
            if isinstance(data, dict):
                results.extend(data.get("Buckets", []) or data.get("Users", []) or data.get("Instances", []) or data.get("SecurityGroups", []))
                next_token = data.get(next_token_key)
            elif isinstance(data, list):
                results.extend(data)
                break
            
            if not next_token:
                break
        
        return results


class AWSProvider:
    def __init__(self, region: str = "us-east-1"):
        self.region = region
        self.cli = AWSCLI()
        self._identity = None
        self.available_regions = get_available_regions()
        self._identity = None
        self.available_regions = get_available_regions()
    
    @property
    def identity(self):
        if self._identity is None:
            self._identity = self.get_caller_identity()
        return self._identity
    
    def get_caller_identity(self):
        return self.cli.run([
            "aws", "sts", "get-caller-identity", "--output", "json"
        ])
    
    def list_buckets(self):
        try:
            result = self.cli.run([
                "aws", "s3api", "list-buckets", "--output", "json"
            ])
            return result.get("Buckets", []) if result else []
        except AWSCLIError:
            return []
    
    def get_bucket_policy(self, bucket_name: str):
        try:
            return self.cli.run([
                "aws", "s3api", "get-bucket-policy",
                "--bucket", bucket_name,
                "--output", "json"
            ])
        except AWSCLIError:
            return None
    
    def get_bucket_acl(self, bucket_name: str):
        try:
            return self.cli.run([
                "aws", "s3api", "get-bucket-acl",
                "--bucket", bucket_name,
                "--output", "json"
            ])
        except AWSCLIError:
            return None
    
    def get_bucketPublicAccessBlock(self, bucket_name: str):
        try:
            return self.cli.run([
                "aws", "s3api", "get-public-access-block",
                "--bucket", bucket_name,
                "--output", "json"
            ])
        except AWSCLIError:
            return None
    
    def get_bucket_encryption(self, bucket_name: str):
        try:
            return self.cli.run([
                "aws", "s3api", "get-bucket-encryption",
                "--bucket", bucket_name,
                "--output", "json"
            ])
        except AWSCLIError:
            return None
    
    def get_bucket_versioning(self, bucket_name: str):
        try:
            return self.cli.run([
                "aws", "s3api", "get-bucket-versioning",
                "--bucket", bucket_name,
                "--output", "json"
            ])
        except AWSCLIError:
            return None
    
    def get_bucket_logging(self, bucket_name: str):
        try:
            return self.cli.run([
                "aws", "s3api", "get-bucket-logging",
                "--bucket", bucket_name,
                "--output", "json"
            ])
        except AWSCLIError:
            return None
    
    def list_users(self):
        return self.cli.run_paginated([
            "aws", "iam", "list-users",
            "--output", "json"
        ])
    
    def list_mfa_devices(self):
        return self.cli.run_paginated([
            "aws", "iam", "list-mfa-devices",
            "--output", "json"
        ])
    
    def get_user(self, user_name: str):
        try:
            return self.cli.run([
                "aws", "iam", "get-user",
                "--user-name", user_name,
                "--output", "json"
            ])
        except AWSCLIError:
            return None
    
    def list_groups_for_user(self, user_name: str):
        return self.cli.run([
            "aws", "iam", "list-groups-for-user",
            "--user-name", user_name,
            "--output", "json"
        ]).get("Groups", [])
    
    def list_roles(self):
        return self.cli.run_paginated([
            "aws", "iam", "list-roles",
            "--output", "json"
        ])
    
    def get_role(self, role_name: str):
        try:
            return self.cli.run([
                "aws", "iam", "get-role",
                "--role-name", role_name,
                "--output", "json"
            ])
        except AWSCLIError:
            return None
    
    def list_attached_role_policies(self, role_name: str):
        return self.cli.run([
            "aws", "iam", "list-attached-role-policies",
            "--role-name", role_name,
            "--output", "json"
        ]).get("AttachedPolicies", [])
    
    def get_account_password_policy(self):
        try:
            return self.cli.run([
                "aws", "iam", "get-account-password-policy",
                "--output", "json"
            ])
        except AWSCLIError:
            return None
    
    def list_access_keys(self, user_name: str):
        keys = self.cli.run([
            "aws", "iam", "list-access-keys",
            "--user-name", user_name,
            "--output", "json"
        ]).get("AccessKeyMetadata", [])
        
        from datetime import datetime
        for key in keys:
            if key.get("CreateDate"):
                try:
                    create_date = datetime.strptime(key["CreateDate"], "%Y-%m-%dT%H:%M:%SZ")
                    days_old = (datetime.now() - create_date).days
                    key["AccessKeyDays"] = days_old
                except:
                    key["AccessKeyDays"] = -1
        
        return keys
    
    def list_security_groups(self):
        return self.cli.run_paginated([
            "aws", "ec2", "describe-security-groups",
            "--output", "json"
        ])
    
    def describe_security_group(self, group_id: str):
        return self.cli.run([
            "aws", "ec2", "describe-security-groups",
            "--group-ids", group_id,
            "--output", "json"
        ]).get("SecurityGroups", [None])[0]
    
    def describe_instances(self):
        return self.cli.run_paginated([
            "aws", "ec2", "describe-instances",
            "--output", "json"
        ])
    
    def describe_instance_status(self, instance_id: str):
        try:
            return self.cli.run([
                "aws", "ec2", "describe-instance-status",
                "--instance-id", instance_id,
                "--output", "json"
            ])
        except AWSCLIError:
            return None
    
    def describe_regions(self):
        return self.cli.run([
            "aws", "ec2", "describe-regions",
            "--output", "json"
        ]).get("Regions", [])
    
    def describe_volumes(self):
        return self.cli.run_paginated([
            "aws", "ec2", "describe-volumes",
            "--output", "json"
        ])
    
    def describe_account_attributes(self, attribute_name: str):
        return self.cli.run([
            "aws", "ec2", "describe-account-attributes",
            "--attribute-names", attribute_name,
            "--output", "json"
        ]).get("AccountAttributes", [])
    
    def describe_db_instances(self):
        return self.cli.run_paginated([
            "aws", "rds", "describe-db-instances",
            "--output", "json"
        ])
    
    def describe_db_snapshots(self):
        return self.cli.run_paginated([
            "aws", "rds", "describe-db-snapshots",
            "--output", "json"
        ])
    
    def describe_log_files(self, db_instance: str):
        try:
            return self.cli.run([
                "aws", "rds", "describe-db-log-files",
                "--db-instance-identifier", db_instance,
                "--output", "json"
            ]).get("DescribeDBLogFiles", [])
        except AWSCLIError:
            return []
    
    def list_trails(self):
        return self.cli.run_paginated([
            "aws", "cloudtrail", "describe-trails",
            "--output", "json"
        ])
    
    def get_trail_status(self, name: str):
        try:
            return self.cli.run([
                "aws", "cloudtrail", "get-trail-status",
                "--name", name,
                "--output", "json"
            ])
        except AWSCLIError:
            return None
    
    def list_functions(self):
        return self.cli.run_paginated([
            "aws", "lambda", "list-functions",
            "--output", "json"
        ])
    
    def get_function(self, function_name: str):
        try:
            return self.cli.run([
                "aws", "lambda", "get-function",
                "--function-name", function_name,
                "--output", "json"
            ])
        except AWSCLIError:
            return None
    
    def get_policy(self, policy_arn: str):
        try:
            return self.cli.run([
                "aws", "iam", "get-policy",
                "--policy-arn", policy_arn,
                "--output", "json"
            ])
        except AWSCLIError:
            return None
    
    def get_policy_version(self, policy_arn: str, version_id: str):
        try:
            return self.cli.run([
                "aws", "iam", "get-policy-version",
                "--policy-arn", policy_arn,
                "--version-id", version_id,
                "--output", "json"
            ])
        except AWSCLIError:
            return None

    def scan(self):
        pass