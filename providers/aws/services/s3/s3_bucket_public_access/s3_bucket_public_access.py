from lib.check.models import Check, Check_Report_AWS
from lib.allowlisters import allowlisters
from providers.aws.services.s3.s3_client import get_s3_client
from providers.aws.aws_provider import AWSProvider


class s3_bucket_public_access(Check):
    def __init__(self):
        super().__init__()
        self.service_name = "s3"
        self._metadata.CheckID = "s3_bucket_public_access"
        self._metadata.CheckTitle = "Ensure S3 buckets do not allow public access"
        self._metadata.CheckType = [
            "Software and Configuration Checks/AWS Security Best Practices"
        ]
        self._metadata.ServiceName = "s3"
        self._metadata.Severity = "critical"
        self._metadata.ResourceType = "AwsS3Bucket"
        self._metadata.ResourceGroup = "storage"
        self._metadata.Description = (
            "Checks if S3 buckets allow public access. "
            "The check fails if the bucket policy or ACL allows public access."
        )
        self._metadata.Risk = (
            "Public buckets can expose sensitive data to the public internet. "
            "Anyone on the internet can read or write to objects in the bucket."
        )
        self._metadata.Categories = ["internet-exposed"]
        self._metadata.Remediation = {
            "Code": {
                "CLI": "aws s3api put-public-access-block --bucket <bucket-name> --public-access-block-configuration 'BlockPublicAcls=true,BlockPublicPolicy=true,IgnorePublicAcls=true,RestrictPublicBuckets=true'"
            },
            "Recommendation": {
                "Text": "Enable S3 Block Public Access on the bucket or account level.",
                "Url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"
            }
        }

    def execute(self):
        findings = []
        client = get_s3_client()
        
        if not client.buckets:
            return findings
        
        for bucket in client.buckets:
            report = Check_Report_AWS(
                check_id=self.CheckID,
                check_metadata=self._metadata,
                resource=bucket
            )
            report.status = "PASS" if not bucket.is_public else "FAIL"
            report.status_extended = (
                f"S3 Bucket {bucket.name} {'does not ' if not bucket.is_public else ''}"
                f"allow public access"
            )
            report.region = bucket.region
            report.resource_id = bucket.name
            report.resource_arn = f"arn:aws:s3:::{bucket.name}"
            
            findings.append(report)
        
        return findings


s3_bucket_public_access_instance = s3_bucket_public_access()