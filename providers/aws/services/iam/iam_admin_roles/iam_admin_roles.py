from lib.check.models import Check, Check_Report_AWS
from providers.aws.services.iam.iam_client import get_iam_client


class iam_admin_roles(Check):
    def __init__(self):
        super().__init__()
        self.service_name = "iam"
        self._metadata.CheckID = "iam_admin_roles"
        self._metadata.CheckTitle = "Ensure IAM admin roles do not have users attached"
        self._metadata.CheckType = [
            "Software and Configuration Checks/Identity and Access Management"
        ]
        self._metadata.ServiceName = "iam"
        self._metadata.Severity = "critical"
        self._metadata.ResourceType = "AwsIamRole"
        self._metadata.ResourceGroup = "IAM"
        self._metadata.Description = (
            "Checks if admin roles have users attached. "
            "Admin roles should be assumed, not assigned directly."
        )
        self._metadata.Risk = (
            "Directly attached admin roles increase security risk. "
            "Users may inadvertently perform privileged actions."
        )
        self._metadata.Categories = ["identity-access"]
        self._metadata.Remediation = {
            "Code": {
                "CLI": "Use role assumption instead of direct role attachment"
            },
            "Recommendation": {
                "Text": "Use role assumption for privileged access.",
                "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use.html"
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
        
        admin_role_names = ["Admin", "Administrator", "admin", "administrator"]
        admin_patterns = ["admin", "poweruser", "full-access"]
        
        for role in client.roles:
            if any(pattern in role.role_name.lower() for pattern in admin_patterns):
                has_admin_policy = False
                for policy_arn in role.policies:
                    if "AdministratorAccess" in str(policy_arn):
                        has_admin_policy = True
                        break
                
                report = Check_Report_AWS(
                    check_id=self.CheckID,
                    check_metadata=self._metadata,
                    resource=role
                )
                report.status = "FAIL" if has_admin_policy else "PASS"
                report.status_extended = (
                    f"IAM Role {role.role_name} has "
                    f"{'AdministratorAccess policy attached' if has_admin_policy else 'no Administrator policy'}"
                )
                report.region = "us-east-1"
                report.resource_id = role.role_name
                report.resource_arn = role.arn
                
                findings.append(report)
        
        return findings


iam_admin_roles_instance = iam_admin_roles()