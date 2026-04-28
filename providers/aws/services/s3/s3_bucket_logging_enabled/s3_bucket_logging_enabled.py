from lib.check.models import Check, Check_Report_AWS
from providers.aws.services.s3.s3_client import get_s3_client


class s3_bucket_logging_enabled(Check):
    def __init__(self):
        super().__init__()
        self.service_name = "s3"
        self._metadata.CheckID = "s3_bucket_logging_enabled"
        self._metadata.CheckTitle = "Ensure S3 buckets have logging enabled"
        self._metadata.CheckType = [
            "Software and Configuration Checks/AWS Security Best Practices"
        ]
        self._metadata.ServiceName = "s3"
        self._metadata.Severity = "medium"
        self._metadata.ResourceType = "AwsS3Bucket"
        self._metadata.ResourceGroup = "storage"
        self._metadata.Description = (
            "Checks if S3 buckets have access logging enabled. "
            "Logging provides audit trail of bucket access."
        )
        self._metadata.Risk = (
            "Without logging, you cannot audit who accessed your buckets. "
            "This makes it difficult to detect unauthorized access."
        )
        self._metadata.Categories = ["logging"]
        self._metadata.Remediation = {
            "Code": {
                "CLI": "aws s3api put-bucket-logging --bucket <bucket-name> --bucket-logging-status '{\"TargetBucket\": \"<logging-bucket>\", \"TargetPrefix\": \"logs/\"}'"
            },
            "Recommendation": {
                "Text": "Enable access logging on S3 buckets.",
                "Url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/logging-with-s3.html"
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
            report.status = "PASS" if bucket.is_logging_enabled else "FAIL"
            report.status_extended = (
                f"S3 Bucket {bucket.name} has "
                f"{'logging enabled' if bucket.is_logging_enabled else 'logging disabled'}"
            )
            report.region = bucket.region
            report.resource_id = bucket.name
            report.resource_arn = f"arn:aws:s3:::{bucket.name}"
            
            findings.append(report)
        
        return findings


s3_bucket_logging_enabled_instance = s3_bucket_logging_enabled()