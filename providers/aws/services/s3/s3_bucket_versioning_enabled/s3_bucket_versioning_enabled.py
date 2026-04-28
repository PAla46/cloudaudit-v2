from lib.check.models import Check, Check_Report_AWS
from providers.aws.services.s3.s3_client import get_s3_client


class s3_bucket_versioning_enabled(Check):
    def __init__(self):
        super().__init__()
        self.service_name = "s3"
        self._metadata.CheckID = "s3_bucket_versioning_enabled"
        self._metadata.CheckTitle = "Ensure S3 bucket versioning is enabled"
        self._metadata.CheckType = [
            "Software and Configuration Checks/AWS Security Best Practices"
        ]
        self._metadata.ServiceName = "s3"
        self._metadata.Severity = "medium"
        self._metadata.ResourceType = "AwsS3Bucket"
        self._metadata.ResourceGroup = "storage"
        self._metadata.Description = (
            "Checks if S3 buckets have versioning enabled. "
            "Versioning protects against accidental deletion and allows you to recover previous versions."
        )
        self._metadata.Risk = (
            "Without versioning, deleted objects cannot be recovered. "
            "This can lead to data loss in case of accidental deletion or overwrite."
        )
        self._metadata.Categories = ["resilience"]
        self._metadata.Remediation = {
            "Code": {
                "CLI": "aws s3api put-bucket-versioning --bucket <bucket-name> --versioning-configuration Status=Enabled"
            },
            "Recommendation": {
                "Text": "Enable versioning on S3 buckets.",
                "Url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/versioning-overview.html"
            }
        }

    def execute(self):
        findings = []
        client = get_s3_client()
        
        for bucket in client.buckets:
            report = Check_Report_AWS(
                check_id=self.CheckID,
                check_metadata=self._metadata,
                resource=bucket
            )
            report.status = "PASS" if bucket.is_versioning_enabled else "FAIL"
            report.status_extended = (
                f"S3 Bucket {bucket.name} has "
                f"{'versioning enabled' if bucket.is_versioning_enabled else 'versioning disabled'}"
            )
            report.region = bucket.region
            report.resource_id = bucket.name
            report.resource_arn = f"arn:aws:s3:::{bucket.name}"
            
            findings.append(report)
        
        return findings


s3_bucket_versioning_enabled_instance = s3_bucket_versioning_enabled()