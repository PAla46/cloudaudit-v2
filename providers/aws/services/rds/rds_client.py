from dataclasses import dataclass
from typing import List

from providers.aws.aws_provider import AWSProvider


@dataclass
class RDSDBInstance:
    db_instance_identifier: str
    db_instance_class: str
    engine: str
    engine_version: str
    db_instance_status: str
    master_username: str
    db_name: str
    endpoint: dict
    storage_encrypted: bool = False
    publicly_accessible: bool = False
    backup_retention_period: int = 0
    multi_az: bool = False
    iam_database_authentication_enabled: bool = False
    deletion_protection: bool = False
    tags: List[dict] = None

    def __post_init__(self):
        if self.tags is None:
            self.tags = []


@dataclass
class RDSSnapshot:
    snapshot_identifier: str
    db_instance_identifier: str
    snapshot_type: str
    status: str
    create_time: str
    encrypted: bool


class RDSClient:
    def __init__(self, provider: AWSProvider):
        self.provider = provider
        self.db_instances: List[RDSDBInstance] = []
        self.snapshots: List[RDSSnapshot] = []
        self.__scan()

    def __scan(self):
        self.db_instances = self._scan_db_instances()
        self.snapshots = self._scan_snapshots()

    def _scan_db_instances(self) -> List[RDSDBInstance]:
        instances = []
        
        try:
            result = self.provider.describe_db_instances()
        except:
            return instances
        
        for db in result.get("DBInstances", []):
            instance = RDSDBInstance(
                db_instance_identifier=db.get("DBInstanceIdentifier", ""),
                db_instance_class=db.get("DBInstanceClass", ""),
                engine=db.get("Engine", ""),
                engine_version=db.get("EngineVersion", ""),
                db_instance_status=db.get("DBInstanceStatus", ""),
                master_username=db.get("MasterUsername", ""),
                db_name=db.get("DBName", ""),
                endpoint=db.get("Endpoint", {}),
                storage_encrypted=db.get("StorageEncrypted", False),
                publicly_accessible=db.get("PubliclyAccessible", False),
                backup_retention_period=db.get("BackupRetentionPeriod", 0),
                multi_az=db.get("MultiAZ", False),
                iam_database_authentication_enabled=db.get("IAMDatabaseAuthenticationEnabled", False),
                deletion_protection=db.get("DeletionProtection", False)
            )
            instances.append(instance)
        
        return instances

    def _scan_snapshots(self) -> List[RDSSnapshot]:
        snapshots = []
        
        try:
            result = self.provider.describe_db_snapshots()
        except:
            return snapshots
        
        for snap in result.get("DBSnapshots", []):
            snapshot = RDSSnapshot(
                snapshot_identifier=snap.get("DBSnapshotIdentifier", ""),
                db_instance_identifier=snap.get("DBInstanceIdentifier", ""),
                snapshot_type=snap.get("SnapshotType", ""),
                status=snap.get("Status", ""),
                create_time=snap.get("SnapshotCreateTime", ""),
                encrypted=snap.get("Encrypted", False)
            )
            snapshots.append(snapshot)
        
        return snapshots


rds_client = None


def get_rds_client(provider: AWSProvider = None):
    global rds_client
    if rds_client is None:
        if provider is None:
            provider = AWSProvider()
        rds_client = RDSClient(provider)
    return rds_client


def set_rds_client(client: RDSClient):
    global rds_client
    rds_client = client