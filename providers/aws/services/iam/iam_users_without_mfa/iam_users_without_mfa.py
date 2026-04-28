from lib.check.models import Check, Check_Report_AWS
from providers.aws.services.iam.iam_client import get_iam_client


class iam_users_without_mfa(Check):
    def __init__(self):
        super().__init__()
        self.service_name = "iam"
        self._metadata.CheckID = "iam_users_without_mfa"
        self._metadata.CheckTitle = "Ensure IAM users have MFA enabled"
        self._metadata.CheckType = [
            "Software and Configuration Checks/Identity and Access Management"
        ]
        self._metadata.ServiceName = "iam"
        self._metadata.Severity = "critical"
        self._metadata.ResourceType = "AwsIamUser"
        self._metadata.ResourceGroup = "IAM"
        self._metadata.Description = (
            "Checks if IAM users have MFA enabled. "
            "MFA adds an extra layer of security."
        )
        self._metadata.Risk = (
            "Without MFA, user accounts are vulnerable to credential theft. "
            "Attackers can use compromised credentials to access resources."
        )
        self._metadata.Categories = ["multi-factor-auth"]
        self._metadata.Remediation = {
            "Code": {
                "CLI": "aws iam enable-mfa-device --user-name <user-name> --serial-number <serial> --TotpCode <code>"
            },
            "Recommendation": {
                "Text": "Enable MFA for all IAM users.",
                "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/console_mfa.html"
            }
        }

    def execute(self):
        findings = []
        
        try:
            client = get_iam_client()
        except Exception as e:
            report = Check_Report_AWS(
                check_id=self.CheckID,
                check_metadata=self._metadata,
                resource=None
            )
            report.status = "UNKNOWN"
            report.status_extended = f"Unable to scan IAM: {str(e)}"
            report.region = "us-east-1"
            findings.append(report)
            return findings
        
        for user in client.users:
            report = Check_Report_AWS(
                check_id=self.CheckID,
                check_metadata=self._metadata,
                resource=user
            )
            report.status = "PASS" if user.has_mfa else "FAIL"
            report.status_extended = (
                f"IAM User {user.user_name} has MFA "
                f"{'enabled' if user.has_mfa else 'disabled'}"
            )
            report.region = "us-east-1"
            report.resource_id = user.user_name
            report.resource_arn = user.arn
            
            findings.append(report)
        
        return findings


iam_users_without_mfa_instance = iam_users_without_mfa()