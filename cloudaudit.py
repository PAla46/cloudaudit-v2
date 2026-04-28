import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib.check.models import Check, Check_Report_AWS, CheckMetadata
from lib.allowlisters import allowlisters
from providers.aws.services.s3.s3_client import s3_client
from providers.aws.services.iam.iam_client import iam_client
from providers.aws.services.ec2.ec2_client import ec2_client
from providers.aws.services.cloudtrail.cloudtrail_client import cloudtrail_client
from providers.aws.services.rds.rds_client import rds_client
from providers.aws.aws_provider import AWSProvider
from output.json import JSONOutput, CSVOutput, HTMLOutput, ComplianceCSVOutput
import json
import argparse
from datetime import datetime


class CloudAudit:
    def __init__(self, provider="aws", output_format="json"):
        self.provider_name = provider
        self.output_format = output_format
        self.provider = None
        self.findings = []
        self.checks = []
        
        self._global_services = ["iam", "cloudtrail", "s3", "route53", "cloudfront", "shield", "waf"]
    
    def _load_checks(self):
        check_classes = []
        
        if self.provider_name == "aws":
            check_classes = self._load_aws_checks()
        
        return check_classes
    
    def _load_aws_checks(self):
        from providers.aws.services.s3.s3_bucket_public_access.s3_bucket_public_access import s3_bucket_public_access
        from providers.aws.services.s3.s3_bucket_server_side_encryption.s3_bucket_server_side_encryption import s3_bucket_server_side_encryption
        from providers.aws.services.s3.s3_bucket_versioning_enabled.s3_bucket_versioning_enabled import s3_bucket_versioning_enabled
        from providers.aws.services.s3.s3_bucket_logging_enabled.s3_bucket_logging_enabled import s3_bucket_logging_enabled
        from providers.aws.services.iam.iam_root_mfa_enabled.iam_root_mfa_enabled import iam_root_mfa_enabled
        from providers.aws.services.iam.iam_password_policy.iam_password_policy import iam_password_policy
        from providers.aws.services.iam.iam_users_without_mfa.iam_users_without_mfa import iam_users_without_mfa
        from providers.aws.services.iam.iam_admin_roles.iam_admin_roles import iam_admin_roles
        from providers.aws.services.ec2.ec2_security_groups_opens_ssh.ec2_security_groups_opens_ssh import ec2_security_groups_opens_ssh
        from providers.aws.services.ec2.ec2_public_ips.ec2_public_ips import ec2_public_ips
        
        return [
            s3_bucket_public_access(),
            s3_bucket_server_side_encryption(),
            s3_bucket_versioning_enabled(),
            s3_bucket_logging_enabled(),
            iam_root_mfa_enabled(),
            iam_password_policy(),
            iam_users_without_mfa(),
            iam_admin_roles(),
            ec2_security_groups_opens_ssh(),
            ec2_public_ips(),
        ]
    
    def run(self, service_filter=None, check_filter=None):
        self.provider = AWSProvider()
        
        if self.provider_name == "aws":
            self.provider.scan()
        
        checks = self._load_checks()
        
        for check in checks:
            if service_filter and check.service_name.lower() != service_filter.lower():
                continue
            if check_filter and check.CheckID.lower() != check_filter.lower():
                continue
            
            try:
                findings = check.execute()
                if not findings:
                    from lib.check.models import Check_Report_AWS
                    report = Check_Report_AWS(
                        check_id=check.CheckID,
                        check_metadata=check._metadata,
                        resource=None
                    )
                    report.status = "PASS"
                    report.status_extended = f"No {check.service_name} issues found"
                    report.region = "us-east-1"
                    report.resource_id = check.service_name
                    findings.append(report)
                self.findings.extend(findings)
            except Exception as e:
                print(f"Error running check {check.CheckID}: {e}", file=sys.stderr)
        
        return self.findings
    
    def output(self, filename=None):
        output_handlers = {
            "json": JSONOutput(),
            "csv": CSVOutput(),
            "html": HTMLOutput(),
        }
        
        handler = output_handlers.get(self.output_format)
        if not handler:
            raise ValueError(f"Unknown output format: {self.output_format}")
        
        return handler.write(self.findings, filename)


def parse_args():
    parser = argparse.ArgumentParser(
        description="CloudAudit - Multi-cloud security auditing tool"
    )
    parser.add_argument(
        "--provider", "-p",
        choices=["aws", "azure", "gcp"],
        default="aws",
        help="Cloud provider to audit"
    )
    parser.add_argument(
        "--output", "-o",
        choices=["json", "csv", "html"],
        default="json",
        help="Output format"
    )
    parser.add_argument(
        "--output-file",
        help="Output file path (default: stdout)"
    )
    parser.add_argument(
        "--service", "-s",
        help="Service to audit (e.g., s3, iam, ec2)"
    )
    parser.add_argument(
        "--check", "-c",
        help="Specific check ID to run (e.g., s3_bucket_public_access)"
    )
    parser.add_argument(
        "--list-checks",
        action="store_true",
        help="List all available checks"
    )
    parser.add_argument(
        "--list-services",
        action="store_true",
        help="List all available services"
    )
    parser.add_argument(
        "--list-compliance",
        action="store_true",
        help="List all compliance frameworks"
    )
    parser.add_argument(
        "--version", "-v",
        action="store_true",
        help="Show version"
    )
    parser.add_argument(
        "--severity",
        choices=["critical", "high", "medium", "low"],
        help="Filter by severity"
    )
    
    return parser.parse_args()


def list_checks(provider="aws"):
    print(f"Available checks for {provider}:")
    print("-" * 60)
    
    checks = {
        "aws": [
            ("s3_bucket_public_access", "S3", "critical", "Ensure S3 buckets do not allow public access"),
            ("s3_bucket_server_side_encryption", "S3", "high", "Ensure S3 buckets have encryption at rest enabled"),
            ("s3_bucket_versioning_enabled", "S3", "medium", "Ensure S3 bucket versioning is enabled"),
            ("s3_bucket_logging_enabled", "S3", "medium", "Ensure S3 buckets have logging enabled"),
            ("iam_root_mfa_enabled", "IAM", "critical", "Ensure MFA is enabled for the root user"),
            ("iam_password_policy", "IAM", "high", "Ensure IAM password policy exists"),
            ("iam_users_without_mfa", "IAM", "critical", "Ensure IAM users have MFA enabled"),
            ("iam_admin_roles", "IAM", "critical", "Ensure IAM admin roles do not have users"),
            ("ec2_security_groups_opens_ssh", "EC2", "high", "Ensure security groups do not allow SSH"),
            ("ec2_public_ips", "EC2", "medium", "Ensure EC2 instances have public IPs"),
        ]
    }
    
    for check_id, service, severity, title in checks.get(provider, []):
        print(f"  [{severity.upper():8}] {check_id:40} ({service}) - {title}")


def list_services(provider="aws"):
    print(f"Available services for {provider}:")
    print("-" * 40)
    
    services = {
        "aws": ["s3", "iam", "ec2", "cloudtrail", "rds", "lambda"]
    }
    
    for service in services.get(provider, []):
        print(f"  - {service}")


def list_compliance():
    print("Available compliance frameworks:")
    print("-" * 40)
    print("  - CIS AWS Foundations Benchmark")
    print("  - PCI DSS")
    print("  - NIST AWS")
    print("  - SOC2")


def main():
    args = parse_args()
    
    if args.version:
        print("CloudAudit 0.1.0")
        return
    
    if args.list_checks:
        list_checks(args.provider)
        return
    
    if args.list_services:
        list_services(args.provider)
        return
    
    if args.list_compliance:
        list_compliance()
        return
    
    print(f"CloudAudit - Starting {args.provider.upper()} audit...", file=sys.stderr)
    
    audit = CloudAudit(provider=args.provider, output_format=args.output)
    findings = audit.run(service_filter=args.service, check_filter=args.check)
    
    if args.severity:
        findings = [f for f in findings if f.severity == args.severity]
    
    audit.findings = findings
    
    account_id = ""
    if args.provider == "aws" and audit.provider:
        try:
            account_id = audit.provider.identity.get("Account", "")
        except:
            pass
    
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    
    output_format = args.output
    output_file = args.output_file
    
    output_handlers = {
        "json": JSONOutput(),
        "csv": CSVOutput(),
        "html": HTMLOutput(),
    }
    
    compliance_handlers = {
        "csv": ComplianceCSVOutput(),
    }
    
    if output_file:
        handler = output_handlers.get(output_format)
        handler.write(findings, output_file, account_id)
    else:
        base_filename = f"cloudaudit-{account_id}-{timestamp}"
        
        for fmt in ["json", "csv", "html"]:
            filename = f"{base_filename}.{fmt}"
            handler = output_handlers.get(fmt)
            handler.write(findings, filename, account_id)
            print(f"Generated: {filename}", file=sys.stderr)
        
        compliance_base = f"cloudaudit-{account_id}-{timestamp}_compliance-cis_aws"
        for fmt in ["csv"]:
            filename = f"{compliance_base}.{fmt}"
            handler = compliance_handlers.get(fmt)
            handler.write(findings, filename, account_id, "cis")
            print(f"Generated: {filename}", file=sys.stderr)


if __name__ == "__main__":
    main()