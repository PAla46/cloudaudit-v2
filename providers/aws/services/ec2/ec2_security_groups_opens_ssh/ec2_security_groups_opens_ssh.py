from lib.check.models import Check, Check_Report_AWS
from providers.aws.services.ec2.ec2_client import get_ec2_client


class ec2_security_groups_opens_ssh(Check):
    def __init__(self):
        super().__init__()
        self.service_name = "ec2"
        self._metadata.CheckID = "ec2_security_groups_opens_ssh"
        self._metadata.CheckTitle = "Ensure security groups do not allow SSH from 0.0.0.0/0"
        self._metadata.CheckType = [
            "Software and Configuration Checks/Network Access Control Lists"
        ]
        self._metadata.ServiceName = "ec2"
        self._metadata.Severity = "high"
        self._metadata.ResourceType = "AwsEc2SecurityGroup"
        self._metadata.ResourceGroup = "network"
        self._metadata.Description = (
            "Checks if security groups allow SSH from 0.0.0.0/0. "
            "Open SSH access can be exploited by attackers."
        )
        self._metadata.Risk = (
            "Security groups open to the internet allow unauthorized SSH access. "
            "This can lead to compromised instances."
        )
        self._metadata.Categories = ["internet-exposed"]
        self._metadata.Remediation = {
            "Code": {
                "CLI": "aws ec2 revoke-security-group-ingress --group-id <group-id> --protocol tcp --port 22 --cidr 0.0.0.0/0"
            },
            "Recommendation": {
                "Text": "Restrict SSH access to specific IPs.",
                "Url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html"
            }
        }

    def execute(self):
        findings = []
        
        try:
            client = get_ec2_client()
        except Exception as e:
            report = Check_Report_AWS(
                check_id=self.CheckID,
                check_metadata=self._metadata,
                resource=None
            )
            report.status = "UNKNOWN"
            report.status_extended = f"Unable to scan EC2: {str(e)}"
            report.region = "us-east-1"
            findings.append(report)
            return findings
        
        for sg in client.security_groups:
            allows_ssh = False
            
            for perm in sg.ip_permissions:
                for ip_range in perm.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        from_port = perm.get("FromPort", 0)
                        to_port = perm.get("ToPort", 0)
                        
                        if from_port <= 22 <= to_port:
                            allows_ssh = True
                            break
                
                if allows_ssh:
                    break
            
            report = Check_Report_AWS(
                check_id=self.CheckID,
                check_metadata=self._metadata,
                resource=sg
            )
            report.status = "FAIL" if allows_ssh else "PASS"
            report.status_extended = (
                f"Security Group {sg.group_name} ({sg.group_id}) "
                f"{'allows SSH from 0.0.0.0/0' if allows_ssh else 'does not allow SSH from 0.0.0.0/0'}"
            )
            report.region = "us-east-1"
            report.resource_id = sg.group_id
            report.resource_arn = f"arn:aws:ec2:us-east-1:{sg.owner_id}:security-group/{sg.group_id}"
            
            findings.append(report)
        
        return findings


ec2_security_groups_opens_ssh_instance = ec2_security_groups_opens_ssh()