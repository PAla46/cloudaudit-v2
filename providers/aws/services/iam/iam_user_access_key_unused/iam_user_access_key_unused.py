from lib.check.models import Check, Check_Report_AWS
from providers.aws.aws_provider import AWSProvider
from datetime import datetime, timedelta

class iam_user_access_key_unused(Check):
    def __init__(self):
        super().__init__()
        self.service_name = "iam"
        self._metadata.CheckID = "iam_user_access_key_unused"
        self._metadata.CheckTitle = "Ensure no unused access keys older than 90 days"
        self._metadata.ServiceName = "iam"
        self._metadata.Severity = "medium"
        self._metadata.ResourceType = "AwsIamUser"

    def execute(self):
        findings = []
        try:
            provider = self.provider if hasattr(self, 'provider') and self.provider else AWSProvider()
            users = provider.list_users()
            cutoff_date = (datetime.now() - timedelta(days=90)).strftime("%Y-%m-%d")
            
            for user in users:
                user_name = user.get("UserName")
                if not user_name:
                    continue
                    
                access_keys = provider.list_access_keys(user_name)
                
                for key in access_keys:
                    key_age_days = key.get("AccessKeyDays", -1)
                    create_date = key.get("CreateDate", "")
                    
                    report = Check_Report_AWS(
                        check_id=self.CheckID,
                        check_metadata=self._metadata,
                        resource=None
                    )
                    report.resource_id = user_name
                    report.resource_arn = f"arn:aws:iam::aws:user/{user_name}"
                    
                    if key_age_days < 0:
                        report.status = "UNKNOWN"
                        report.status_extended = f"Unable to determine age for key"
                    elif key_age_days > 90:
                        report.status = "FAIL"
                        report.status_extended = f"Access key for user {user_name} unused for {key_age_days} days (>{cutoff_date})"
                    else:
                        report.status = "PASS"
                        report.status_extended = f"Access key for user {user_name} is recent ({key_age_days} days)"
                    
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

iam_user_access_key_unused_instance = iam_user_access_key_unused()