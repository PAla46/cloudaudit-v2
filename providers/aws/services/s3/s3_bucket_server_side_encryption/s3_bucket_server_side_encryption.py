from lib.check.models import Check, Check_Report_AWS
from providers.aws.services.s3.s3_client import get_s3_client


class s3_bucket_server_side_encryption(Check):
    def __init__(self):
        super().__init__()
        self.service_name = "s3"
        self._metadata.CheckID = "s3_bucket_server_side_encryption"
        self._metadata.CheckTitle = "Ensure S3 buckets have encryption at rest enabled"
        self._metadata.CheckType = [
            "Software and Configuration Checks/AWS Security Best Practices"
        ]
        self._metadata.ServiceName = "s3"
        self._metadata.Severity = "high"
        self._metadata.ResourceType = "AwsS3Bucket"
        self._metadata.ResourceGroup = "storage"
        self._metadata.Description = (
            "Checks if S3 buckets have server-side encryption enabled. "
            "The check passes if encryption is enabled with AWS S3 or KMS."
        )
        self._metadata.Risk = (
            "Unencrypted data at rest can be accessed by unauthorized users. "
            "This can lead to data breach and compliance violations."
        )
        self._metadata.Categories = ["encryption"]
        self._metadata.Remediation = {
            "Code": {
                "CLI": "aws s3api put-bucket-encryption --bucket <bucket-name> --server-side-encryption-configuration '{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"AES256\"}}]'"
            },
            "Recommendation": {
                "Text": "Enable default encryption on S3 buckets.",
                "Url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/serv-side-encryption.html"
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
            report.status = "PASS" if bucket.is_encrypted else "FAIL"
            report.status_extended = (
                f"S3 Bucket {bucket.name} has "
                f"{'encryption enabled' if bucket.is_encrypted else 'encryption disabled'}"
            )
            report.region = bucket.region
            report.resource_id = bucket.name
            report.resource_arn = f"arn:aws:s3:::{bucket.name}"
            
            findings.append(report)
        
        return findings


s3_bucket_server_side_encryption_instance = s3_bucket_server_side_encryption()