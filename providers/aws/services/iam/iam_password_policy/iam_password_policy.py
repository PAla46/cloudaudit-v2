from lib.check.models import Check, Check_Report_AWS


class iam_password_policy(Check):
    def __init__(self):
        super().__init__()
        self.service_name = "iam"
        self._metadata.CheckID = "iam_password_policy"
        self._metadata.CheckTitle = "Ensure IAM password policy exists"
        self._metadata.CheckType = [
            "Software and Configuration Checks/Identity and Access Management"
        ]
        self._metadata.ServiceName = "iam"
        self._metadata.Severity = "high"
        self._metadata.ResourceType = "AwsIamPasswordPolicy"
        self._metadata.ResourceGroup = "IAM"
        self._metadata.Description = (
            "Checks if IAM password policy exists. "
            "A strong password policy reduces the risk of compromise."
        )
        self._metadata.Risk = (
            "Without a password policy, users may use weak passwords. "
            "This increases the risk of unauthorized access."
        )
        self._metadata.Categories = ["passwords"]
        self._metadata.Remediation = {
            "Code": {
                "CLI": "aws iam update-account-password-policy --minimum-password-length 14 --require-uppercase-characters --require-lowercase-characters --require-numbers --require-symbols --max-age 90"
            },
            "Recommendation": {
                "Text": "Create an IAM password policy.",
                "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/console_password_policies.html"
            }
        }

    def execute(self):
        findings = []
        
        try:
            from providers.aws.services.iam.iam_client import get_iam_client
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
            report.resource_id = "account-password-policy"
            findings.append(report)
            return findings
        
        has_policy = client.password_policy is not None
        
        report = Check_Report_AWS(
            check_id=self.CheckID,
            check_metadata=self._metadata,
            resource=None
        )
        report.status = "PASS" if has_policy else "FAIL"
        report.status_extended = (
            f"IAM password policy is {'present' if has_policy else 'not present'}"
        )
        report.region = "us-east-1"
        report.resource_id = "account-password-policy"
        report.resource_arn = f"arn:aws:iam::aws:policy/account-password-policy"
        
        findings.append(report)
        return findings


iam_password_policy_instance = iam_password_policy()