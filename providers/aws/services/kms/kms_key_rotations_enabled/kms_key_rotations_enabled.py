from lib.check.models import Check, Check_Report_AWS
from providers.aws.aws_provider import AWSProvider

class kms_key_rotations_enabled(Check):
    def __init__(self):
        super().__init__()
        self.service_name = "kms"
        self._metadata.CheckID = "kms_key_rotations_enabled"
        self._metadata.CheckTitle = "Ensure KMS key rotation is enabled"
        self._metadata.ServiceName = "kms"
        self._metadata.Severity = "medium"
        self._metadata.ResourceType = "AwsKmsKey"

    def execute(self):
        findings = []
        try:
            provider = getattr(self, 'provider', None) or AWSProvider()
            
            result = provider.cli.run([
                "aws", "kms", "list-keys",
                "--output", "json"
            ])
            
            keys = result.get("Keys", [])
            
            for key in keys:
                key_id = key.get("KeyId")
                
                report = Check_Report_AWS(
                    check_id=self.CheckID,
                    check_metadata=self._metadata,
                    resource=key_id
                )
                report.resource_id = key_id
                report.resource_arn = f"arn:aws:kms:us-east-1:123456789012:key/{key_id}"
                
                try:
                    key_info = provider.cli.run([
                        "aws", "kms", "describe-key",
                        "--key-id", key_id,
                        "--output", "json"
                    ])
                    
                    key_metadata = key_info.get("KeyMetadata", {})
                    rotation_enabled = key_metadata.get("KeyRotationEnabled", False)
                    
                    if rotation_enabled:
                        report.status = "PASS"
                        report.status_extended = f"KMS key {key_id} has rotation enabled"
                    else:
                        report.status = "FAIL"
                        report.status_extended = f"KMS key {key_id} does not have rotation enabled"
                        
                except Exception as e:
                    report.status = "UNKNOWN"
                    report.status_extended = f"Unable to check: {str(e)}"
                
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

kms_key_rotations_enabled_instance = kms_key_rotations_enabled()