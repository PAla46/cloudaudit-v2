import json
from dataclasses import dataclass, field
from typing import List, Optional

from providers.aws.aws_provider import AWSProvider


@dataclass
class IAMUser:
    arn: str
    user_id: str
    user_name: str
    create_date: str
    password_last_used: Optional[str] = None
    mfa_devices: List[dict] = field(default_factory=list)
    access_keys: List[dict] = field(default_factory=list)
    groups: List[str] = field(default_factory=list)

    @property
    def has_mfa(self):
        return len(self.mfa_devices) > 0


@dataclass
class IAMRole:
    arn: str
    role_id: str
    role_name: str
    create_date: str
    path: str = ""
    policies: List[str] = field(default_factory=list)

    @property
    def is_admin(self):
        return "*" in str(self.policies)


class IAMClient:
    def __init__(self, provider: AWSProvider):
        self.provider = provider
        self.users: List[IAMUser] = []
        self.roles: List[IAMRole] = []
        self.password_policy = None
        self.__scan()

    def __scan(self):
        self.users = self._scan_users()
        self.roles = self._scan_roles()
        
        try:
            self.password_policy = self.provider.get_account_password_policy()
        except:
            self.password_policy = None

    def _scan_users(self) -> List[IAMUser]:
        users = []
        users_data = self.provider.list_users()
        
        user: dict
        for user in users_data:
            user_name = user.get("UserName")
            if not user_name:
                continue
            
            iam_user = IAMUser(
                arn=user.get("Arn", ""),
                user_id=user.get("UserId", ""),
                user_name=user_name,
                create_date=user.get("CreateDate", "")
            )
            
            mfa_devices = self.provider.list_mfa_devices()
            for mfa in mfa_devices.get("MFADevices", []):
                if mfa.get("UserName") == user_name:
                    iam_user.mfa_devices.append(mfa)
            
            groups = self.provider.list_groups_for_user(user_name)
            iam_user.groups = [g.get("GroupName") for g in groups]
            
            access_keys = self.provider.list_access_keys(user_name)
            iam_user.access_keys = access_keys.get("AccessKeyMetadata", [])
            
            users.append(iam_user)
        
        return users

    def _scan_roles(self) -> List[IAMRole]:
        roles = []
        roles_data = self.provider.list_roles()
        
        role: dict
        for role in roles_data:
            role_name = role.get("RoleName")
            if not role_name:
                continue
            
            iam_role = IAMRole(
                arn=role.get("Arn", ""),
                role_id=role.get("RoleId", ""),
                role_name=role_name,
                create_date=role.get("CreateDate", ""),
                path=role.get("Path", "")
            )
            
            attached_policies = self.provider.list_attached_role_policies(role_name)
            iam_role.policies = [p.get("PolicyArn") for p in attached_policies]
            
            roles.append(iam_role)
        
        return roles


iam_client = None


def get_iam_client(provider: AWSProvider = None):
    global iam_client
    if iam_client is None:
        if provider is None:
            provider = AWSProvider()
        iam_client = IAMClient(provider)
    return iam_client


def set_iam_client(client: IAMClient):
    global iam_client
    iam_client = client