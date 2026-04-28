import json
from dataclasses import dataclass, field
from typing import List, Optional

from providers.aws.aws_provider import AWSProvider


@dataclass
class CloudTrailTrail:
    name: str
    s3_bucket_name: str
    s3_key_prefix: str = ""
    is_multi_region: bool = False
    is_log_file_validation_enabled: bool = False
    cloud_watch_logs_group: str = ""
    cloud_watch_logs_role: str = ""
    kms_key_id: str = ""
    home_region: str = ""
    region: str = ""

    @property
    def is_enabled(self):
        try:
            status = self._get_status()
            return status.get("IsLogging", False) if status else False
        except:
            return False
    
    @property
    def is_not_empty(self):
        status = self._get_status()
        return status and status.get("LatestDeliveryAttempt", "") != ""


class CloudTrailClient:
    def __init__(self, provider: AWSProvider):
        self.provider = provider
        self.trails: List[CloudTrailTrail] = []
        self.__scan()

    def __scan(self):
        trails_data = self.provider.list_trails()
        
        for trail in trails_data:
            ct = CloudTrailTrail(
                name=trail.get("Name", ""),
                s3_bucket_name=trail.get("S3BucketName", ""),
                s3_key_prefix=trail.get("S3KeyPrefix", ""),
                is_multi_region=trail.get("IsMultiRegionTrail", False),
                is_log_file_validation_enabled=trail.get("LogFileValidationEnabled", False),
                cloud_watch_logs_group=trail.get("CloudWatchLogsLogGroupArn", ""),
                cloud_watch_logs_role=trail.get("CloudWatchLogsRoleArn", ""),
                kms_key_id=trail.get("KmsKeyId", ""),
                home_region=trail.get("HomeRegion", ""),
                region=trail.get("TrailARN", "").split(":")[3] if trail.get("TrailARN") else ""
            )
            
            self.trails.append(ct)
    
    def _get_status(self, name: str = None):
        if name is None and self.trails:
            name = self.trails[0].name
        
        if name:
            return self.provider.get_trail_status(name)
        return None


cloudtrail_client = None


def get_cloudtrail_client(provider: AWSProvider = None):
    global cloudtrail_client
    if cloudtrail_client is None:
        if provider is None:
            provider = AWSProvider()
        cloudtrail_client = CloudTrailClient(provider)
    return cloudtrail_client


def set_cloudtrail_client(client: CloudTrailClient):
    global cloudtrail_client
    cloudtrail_client = client