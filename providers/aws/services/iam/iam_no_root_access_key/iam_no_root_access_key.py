from lib.check.models import Check, Check_Report_AWS

class iam_no_root_access_key(Check):
    def __init__(self):
        super().__init__()
        self.service_name = "iam"
        self._metadata.CheckID = "iam_no_root_access_key"
        self._metadata.CheckTitle = "Ensure no root access keys exist"
        self._metadata.ServiceName = "iam"
        self._metadata.Severity = "critical"
        self._metadata.ResourceType = "AwsIamRoot"
        self._metadata.Description = "Checks if root user has access keys."

    def execute(self):
        findings = []
        try:
            provider = self.provider or __import__('providers.aws.aws_provider', fromlist=['AWSProvider']).AWSProvider()
            access_keys = provider.list_access_keys("root")
            
            report = Check_Report_AWS(
                check_id=self.CheckID,
                check_metadata=self._metadata,
                resource=None
            )
            
            if access_keys:
                report.status = "FAIL"
                report.status_extended = f"Root user has {len(access_keys)} access key(s)"
            else:
                report.status = "PASS"
                report.status_extended = "Root user has no access keys"
            
            report.region = "us-east-1"
            report.resource_id = "root"
            findings.append(report)
            
        except Exception as e:
            report = Check_Report_AWS(
                check_id=self.CheckID,
                check_metadata=self._metadata,
                resource=None
            )
            report.status = "UNKNOWN"
            report.status_extended = f"Unable to check: {str(e)}"
            findings.append(report)
        
        return findings

iam_no_root_access_key_instance = iam_no_root_access_key()