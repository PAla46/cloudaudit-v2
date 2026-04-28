from lib.check.models import Check, Check_Report_AWS

class cloudtrail_enabled(Check):
    def __init__(self):
        super().__init__()
        self.service_name = "cloudtrail"
        self._metadata.CheckID = "cloudtrail_enabled"
        self._metadata.CheckTitle = "Ensure CloudTrail is enabled"
        self._metadata.ServiceName = "cloudtrail"
        self._metadata.Severity = "critical"
        self._metadata.ResourceType = "AwsCloudTrail"

    def execute(self):
        findings = []
        try:
            provider = self.provider if hasattr(self, 'provider') and self.provider else __import__('providers.aws.aws_provider', fromlist=['AWSProvider']).AWSProvider()
            trails = provider.list_trails()
            
            if not trails:
                report = Check_Report_AWS(
                    check_id=self.CheckID,
                    check_metadata=self._metadata,
                    resource=None
                )
                report.status = "FAIL"
                report.status_extended = "No CloudTrail trails found"
                report.region = "us-east-1"
                findings.append(report)
            else:
                for trail in trails:
                    trail_name = trail.get("Name")
                    
                    report = Check_Report_AWS(
                        check_id=self.CheckID,
                        check_metadata=self._metadata,
                        resource=trail_name
                    )
                    report.resource_id = trail_name
                    report.resource_arn = f"arn:aws:cloudtrail:::trail/{trail_name}"
                    
                    is_logging = trail.get("IsLogging", False)
                    if is_logging:
                        report.status = "PASS"
                        report.status_extended = f"CloudTrail {trail_name} is logging"
                    else:
                        report.status = "FAIL"
                        report.status_extended = f"CloudTrail {trail_name} is NOT logging"
                    
                    report.region = trail.get("HomeRegion", "us-east-1")
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

cloudtrail_enabled_instance = cloudtrail_enabled()