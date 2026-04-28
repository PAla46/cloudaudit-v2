from lib.check.models import Check, Check_Report_AWS
from providers.aws.aws_provider import AWSProvider

class rds_instance_encryption(Check):
    def __init__(self):
        super().__init__()
        self.service_name = "rds"
        self._metadata.CheckID = "rds_instance_encryption_enabled"
        self._metadata.CheckTitle = "Ensure RDS instances have encryption enabled"
        self._metadata.ServiceName = "rds"
        self._metadata.Severity = "high"
        self._metadata.ResourceType = "AwsRdsDbInstance"

    def execute(self):
        findings = []
        try:
            provider = getattr(self, 'provider', None) or AWSProvider()
            instances = provider.describe_db_instances()
            
            for instance in instances:
                db_name = instance.get("DBInstanceIdentifier")
                
                report = Check_Report_AWS(
                    check_id=self.CheckID,
                    check_metadata=self._metadata,
                    resource=db_name
                )
                report.resource_id = db_name
                
                storage_encrypted = instance.get("StorageEncrypted", False)
                
                if storage_encrypted:
                    report.status = "PASS"
                    report.status_extended = f"RDS instance {db_name} has encryption enabled"
                else:
                    report.status = "FAIL"
                    report.status_extended = f"RDS instance {db_name} does NOT have encryption enabled"
                
                report.region = instance.get("AvailabilityZone", "us-east-1")[:9]
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

rds_instance_encryption_instance = rds_instance_encryption()