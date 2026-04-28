import json
from dataclasses import dataclass, field
from typing import List, Optional

from providers.aws.aws_provider import AWSProvider


@dataclass
class EC2SecurityGroup:
    group_id: str
    group_name: str
    description: str
    vpc_id: str
    owner_id: str
    ip_permissions: List[dict] = field(default_factory=list)
    ip_permissions_egress: List[dict] = field(default_factory=list)
    tags: List[dict] = field(default_factory=list)

    @property
    def allows_ssh(self):
        for perm in self.ip_permissions:
            for ip in perm.get("IpRanges", []):
                if ip.get("CidrIp") == "0.0.0.0/0":
                    for port_range in perm.get("FromPort", []):
                        if 22 >= port_range.get("FromPort", 0):
                            return True
        return False


@dataclass
class EC2Instance:
    instance_id: str
    instance_type: str
    state: str
    tags: List[dict] = field(default_factory=list)
    security_groups: List[str] = field(default_factory=list)
    subnet_id: str = ""
    vpc_id: str = ""
    public_ip: str = ""
    private_ip: str = ""
    image_id: str = ""
    iam_instance_profile: str = ""

    @property
    def has_public_ip(self):
        return bool(self.public_ip)

    @property
    def is_running(self):
        return self.state == "running"


class EC2Client:
    def __init__(self, provider: AWSProvider):
        self.provider = provider
        self.security_groups: List[EC2SecurityGroup] = []
        self.instances: List[EC2Instance] = []
        self.regions: List[str] = []
        self.__scan()

    def __scan(self):
        self.security_groups = self._scan_security_groups()
        self.instances = self._scan_instances()
        
        try:
            regions = self.provider.describe_regions()
            self.regions = [r.get("RegionName") for r in regions]
        except:
            self.regions = ["us-east-1"]

    def _scan_security_groups(self) -> List[EC2SecurityGroup]:
        groups = []
        groups_data = self.provider.list_security_groups()
        
        for sg in groups_data:
            group_id = sg.get("GroupId")
            if not group_id:
                continue
            
            ec2_sg = EC2SecurityGroup(
                group_id=group_id,
                group_name=sg.get("GroupName", ""),
                description=sg.get("Description", ""),
                vpc_id=sg.get("VpcId", ""),
                owner_id=sg.get("OwnerId", ""),
                ip_permissions=sg.get("IpPermissions", []),
                ip_permissions_egress=sg.get("IpPermissionsEgress", []),
                tags=sg.get("Tags", [])
            )
            
            groups.append(ec2_sg)
        
        return groups

    def _scan_instances(self) -> List[EC2Instance]:
        instances = []
        reservations = self.provider.describe_instances()
        
        for reservation in reservations:
            for instance in reservation.get("Instances", []):
                instance_id = instance.get("InstanceId")
                if not instance_id:
                    continue
                
                ec2_instance = EC2Instance(
                    instance_id=instance_id,
                    instance_type=instance.get("InstanceType", ""),
                    state=instance.get("State", {}).get("Name", ""),
                    tags=instance.get("Tags", []),
                    subnet_id=instance.get("SubnetId", ""),
                    vpc_id=instance.get("VpcId", ""),
                    public_ip=instance.get("PublicIpAddress", ""),
                    private_ip=instance.get("PrivateIpAddress", ""),
                    image_id=instance.get("ImageId", "")
                )
                
                sgs = instance.get("SecurityGroups", [])
                ec2_instance.security_groups = [sg.get("GroupId") for sg in sgs]
                
                if instance.get("IamInstanceProfile"):
                    ec2_instance.iam_instance_profile = instance.get("IamInstanceProfile", {}).get("Arn", "")
                
                instances.append(ec2_instance)
        
        return instances


ec2_client = None


def get_ec2_client(provider: AWSProvider = None):
    global ec2_client
    if ec2_client is None:
        if provider is None:
            provider = AWSProvider()
        ec2_client = EC2Client(provider)
    return ec2_client


def set_ec2_client(client: EC2Client):
    global ec2_client
    ec2_client = client