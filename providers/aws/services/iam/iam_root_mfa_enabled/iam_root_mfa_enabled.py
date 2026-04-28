from lib.check.models import Check, Check_Report_AWS, CheckMetadata
from providers.aws.services.iam.iam_client import get_iam_client


class iam_root_mfa_enabled(Check):
    def __init__(self):
        super().__init__()
        self.service_name = "iam"
        self._metadata.CheckID = "iam_root_mfa_enabled"
        self._metadata.CheckTitle = "Ensure MFA is enabled for the root user"
        self._metadata.CheckType = [
            "Software and Configuration Checks/Identity and Access Management"
        ]
        self._metadata.ServiceName = "iam"
        self._metadata.Severity = "critical"
        self._metadata.ResourceType = "AwsIamRoot"
        self._metadata.ResourceGroup = "IAM"
        self._metadata.Description = (
            "Checks if the root user has MFA enabled. "
            "The root account should have MFA enabled to prevent unauthorized access."
        )
        self._metadata.Risk = (
            "Without MFA, the root account is vulnerable to attackers. "
            "Compromised root credentials can lead to complete account takeover."
        )
        self._metadata.Categories = ["multi-factor-auth"]
        self._metadata.Remediation = {
            "Code": {
                "CLI": "aws iam enable-mfa-device --root --serial-number <serial> --TotpCode <code>"
            },
            "Recommendation": {
                "Text": "Enable MFA for the root account.",
                "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-credentials.html"
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
            report.resource_id = "root"
            findings.append(report)
            return findings
        
        has_mfa = False
        try:
            mfa_devices = client.provider.list_mfa_devices()
            if mfa_devices.get("MFADevices"):
                for mfa in mfa_devices["MFADevices"]:
                    if mfa.get("UserName") == "root":
                        has_mfa = True
                        break
        except:
            pass
        
        report = Check_Report_AWS(
            check_id=self.CheckID,
            check_metadata=self._metadata,
            resource=None
        )
        report.status = "PASS" if has_mfa else "FAIL"
        report.status_extended = (
            f"Root account has MFA {'enabled' if has_mfa else 'disabled'}"
        )
        report.region = "us-east-1"
        report.resource_id = "root"
        report.resource_arn = f"arn:aws:iam::aws:root"
        
        findings.append(report)
        return findings


iam_root_mfa_enabled_instance = iam_root_mfa_enabled()