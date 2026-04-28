from lib.check.models import Check, Check_Report_AWS
from providers.aws.aws_provider import AWSProvider

class ec2_security_group_opens(Check):
    def __init__(self, port=22, protocol="tcp"):
        super().__init__()
        self.service_name = "ec2"
        self._metadata.CheckID = f"ec2_security_group_opens_port_{port}"
        self._metadata.CheckTitle = f"Ensure security group does not allow open port {port}"
        self._metadata.ServiceName = "ec2"
        self._metadata.Severity = "high"
        self._metadata.ResourceType = "AwsEc2SecurityGroup"
        self.port = port
        self.protocol = protocol

    def execute(self):
        findings = []
        try:
            provider = getattr(self, 'provider', None) or AWSProvider()
            security_groups = provider.list_security_groups()
            
            for sg in security_groups:
                sg_id = sg.get("GroupId")
                sg_name = sg.get("GroupName")
                
                permissions = sg.get("IpPermissions", []) + sg.get("IpPermissionsEgress", [])
                
                for perm in permissions:
                    from_port = perm.get("FromPort", 0)
                    to_port = perm.get("ToPort", 65535)
                    ip_ranges = perm.get("IpRanges", [])
                    
                    for ip in ip_ranges:
                        cidr = ip.get("CidrIp", "")
                        
                        if cidr == "0.0.0.0/0" and (from_port <= self.port <= to_port):
                            report = Check_Report_AWS(
                                check_id=self.CheckID,
                                check_metadata=self._metadata,
                                resource=sg_id
                            )
                            report.status = "FAIL"
                            report.status_extended = f"Security group {sg_name} ({sg_id}) allows port {self.port} from 0.0.0.0/0"
                            report.resource_id = sg_id
                            report.resource_arn = f"arn:aws:ec2:us-east-1:123456789012:security-group/{sg_id}"
                            report.region = "us-east-1"
                            findings.append(report)
                            break
                    
                    if self.port in range(from_port, to_port + 1) and cidr == "0.0.0.0/0":
                        break
                        
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

ec2_security_group_opens_ssh_instance = ec2_security_group_opens(port=22)
ec2_security_group_opens_rdp_instance = ec2_security_group_opens(port=3389)
ec2_security_group_opens_ftp_instance = ec2_security_group_opens(port=21)