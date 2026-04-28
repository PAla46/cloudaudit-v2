import json
from dataclasses import dataclass, field
from typing import List, Optional

from providers.aws.aws_provider import AWSProvider, AWSCLI


@dataclass
class S3Bucket:
    name: str
    creation_date: str
    region: str = "us-east-1"
    policy: Optional[dict] = None
    acl: Optional[dict] = None
    public_access_block: Optional[dict] = None
    encryption: Optional[dict] = None
    versioning: Optional[dict] = None
    logging: Optional[dict] = None
    tags: List[dict] = field(default_factory=list)

    @property
    def is_public(self):
        if self.public_access_block:
            public_access_block_config = self.public_access_block.get("PublicAccessBlockConfiguration", {})
            if public_access_block_config.get("BlockPublicAcls", False) is False:
                return True
        
        if self.acl:
            for grant in self.acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                if "AllUsers" in grantee.get("URI", ""):
                    return True
        
        if self.policy:
            try:
                policy = json.loads(self.policy.get("Policy", "{}"))
                for statement in policy.get("Statement", []):
                    if statement.get("Effect") == "Allow":
                        principal = statement.get("Principal", {})
                        if principal == "*" or "AllUsers" in str(principal):
                            return True
            except (json.JSONDecodeError, KeyError):
                pass
        
        return False

    @property
    def is_encrypted(self):
        return self.encryption is not None

    @property
    def is_versioning_enabled(self):
        return self.versioning and self.versioning.get("Status") == "Enabled"

    @property
    def is_logging_enabled(self):
        return self.logging and "TargetBucket" in self.logging


class S3Client:
    def __init__(self, provider: AWSProvider):
        self.provider = provider
        self.buckets: List[S3Bucket] = []
        self.region = provider.region
        self.__scan()

    def __scan(self):
        buckets_data = self.provider.list_buckets()
        
        for bucket_data in buckets_data:
            bucket_name = bucket_data.get("Name")
            if not bucket_name:
                continue
            
            bucket = S3Bucket(
                name=bucket_name,
                creation_date=bucket_data.get("CreationDate", ""),
                region=self.region
            )
            
            try:
                bucket.policy = self.provider.get_bucket_policy(bucket_name)
            except:
                pass
            
            try:
                bucket.acl = self.provider.get_bucket_acl(bucket_name)
            except:
                pass
            
            try:
                bucket.public_access_block = self.provider.get_bucketPublicAccessBlock(bucket_name)
            except:
                pass
            
            try:
                bucket.encryption = self.provider.get_bucket_encryption(bucket_name)
            except:
                pass
            
            try:
                bucket.versioning = self.provider.get_bucket_versioning(bucket_name)
            except:
                pass
            
            try:
                bucket.logging = self.provider.get_bucket_logging(bucket_name)
            except:
                pass
            
            self.buckets.append(bucket)


s3_client = None


def get_s3_client(provider: AWSProvider = None):
    global s3_client
    if s3_client is None:
        if provider is None:
            provider = AWSProvider()
        s3_client = S3Client(provider)
    return s3_client


def set_s3_client(client: S3Client):
    global s3_client
    s3_client = client