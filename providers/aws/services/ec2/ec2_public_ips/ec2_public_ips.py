from lib.check.models import Check, Check_Report_AWS
from providers.aws.services.ec2.ec2_client import get_ec2_client


class ec2_public_ips(Check):
    def __init__(self):
        super().__init__()
        self.service_name = "ec2"
        self._metadata.CheckID = "ec2_public_ips"
        self._metadata.CheckTitle = "Ensure EC2 instances do not have public IPs"
        self._metadata.CheckType = [
            "Software and Configuration Checks/AWS Security Best Practices"
        ]
        self._metadata.ServiceName = "ec2"
        self._metadata.Severity = "medium"
        self._metadata.ResourceType = "AwsEc2Instance"
        self._metadata.ResourceGroup = "compute"
        self._metadata.Description = (
            "Checks if EC2 instances have public IPs. "
            "Public IPs expose instances directly to the internet."
        )
        self._metadata.Risk = (
            "Public IPs make instances directly accessible from the internet. "
            "This can lead to unauthorized access and attacks."
        )
        self._metadata.Categories = ["internet-exposed"]
        self._metadata.Remediation = {
            "Code": {
                "CLI": "Use VPC endpoints or bastion hosts instead of public IPs"
            },
            "Recommendation": {
                "Text": "Use private IPs with VPC endpoints or bastion hosts.",
                "Url": "https://docs.aws.amazon.com/vpc/latest/userguide/vpc-ip-addressing.html"
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
        
        for instance in client.instances:
            report = Check_Report_AWS(
                check_id=self.CheckID,
                check_metadata=self._metadata,
                resource=instance
            )
            report.status = "FAIL" if instance.has_public_ip else "PASS"
            report.status_extended = (
                f"EC2 Instance {instance.instance_id} has "
                f"{'public IP ' + instance.public_ip if instance.has_public_ip else 'no public IP'}"
            )
            report.region = "us-east-1"
            report.resource_id = instance.instance_id
            
            findings.append(report)
        
        return findings


ec2_public_ips_instance = ec2_public_ips()