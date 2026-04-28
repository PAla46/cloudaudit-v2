from lib.check.models import Check, Check_Report_AWS

class s3_bucket_default_encryption(Check):
    def __init__(self):
        super().__init__()
        self.service_name = "s3"
        self._metadata.CheckID = "s3_bucket_default_encryption"
        self._metadata.CheckTitle = "Ensure S3 bucket has default encryption enabled"
        self._metadata.ServiceName = "s3"
        self._metadata.Severity = "high"
        self._metadata.ResourceType = "AwsS3Bucket"

    def execute(self):
        findings = []
        try:
            provider = self.provider if hasattr(self, 'provider') and self.provider else __import__('providers.aws.aws_provider', fromlist=['AWSProvider']).AWSProvider()
            buckets = provider.list_buckets()
            
            for bucket in buckets:
                bucket_name = bucket.get("Name")
                
                report = Check_Report_AWS(
                    check_id=self.CheckID,
                    check_metadata=self._metadata,
                    resource=bucket_name
                )
                report.resource_id = bucket_name
                report.resource_arn = f"arn:aws:s3:::{bucket_name}"
                
                try:
                    encryption = provider.get_bucket_encryption(bucket_name)
                    if encryption and encryption.get("ServerSideEncryptionConfiguration"):
                        report.status = "PASS"
                        report.status_extended = f"S3 bucket {bucket_name} has encryption enabled"
                    else:
                        report.status = "FAIL"
                        report.status_extended = f"S3 bucket {bucket_name} does not have default encryption"
                except:
                    report.status = "FAIL"
                    report.status_extended = f"S3 bucket {bucket_name} does not have default encryption"
                
                report.region = "us-east-1"
                findings.append(report)
                
        except Exception as e:
            report = Check_Report_AWS(
                check_id=self.CheckID,
                check_metadata=self._metadata,
                resource=None
            )
            report.status = "UNKNOWN"
            report.status_extended = f"Error: {str(e)}"
            findings.append(report)
        
        return findings

s3_bucket_default_encryption_instance = s3_bucket_default_encryption()