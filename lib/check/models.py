import json
import os
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class CheckMetadata:
    Provider: str = ""
    CheckID: str = ""
    CheckTitle: str = ""
    CheckType: list = field(default_factory=list)
    ServiceName: str = ""
    SubServiceName: str = ""
    ResourceIdTemplate: str = ""
    Severity: str = ""
    ResourceType: str = ""
    ResourceGroup: str = ""
    Description: str = ""
    Risk: str = ""
    RelatedUrl: str = ""
    AdditionalURLs: list = field(default_factory=list)
    Remediation: dict = field(default_factory=dict)
    Categories: list = field(default_factory=list)
    DependsOn: list = field(default_factory=list)
    RelatedTo: list = field(default_factory=list)
    Notes: str = ""

    @classmethod
    def from_file(cls, metadata_file: str):
        if os.path.exists(metadata_file):
            with open(metadata_file, "r") as f:
                data = json.load(f)
                return cls(**{k: v for k, v in data.items() if k != "Recommendation"})
        return cls()

    def to_dict(self):
        return {
            "Provider": self.Provider,
            "CheckID": self.CheckID,
            "CheckTitle": self.CheckTitle,
            "CheckType": self.CheckType,
            "ServiceName": self.ServiceName,
            "SubServiceName": self.SubServiceName,
            "ResourceIdTemplate": self.ResourceIdTemplate,
            "Severity": self.Severity,
            "ResourceType": self.ResourceType,
            "ResourceGroup": self.ResourceGroup,
            "Description": self.Description,
            "Risk": self.Risk,
            "RelatedUrl": self.RelatedUrl,
            "AdditionalURLs": self.AdditionalURLs,
            "Remediation": self.Remediation,
            "Categories": self.Categories,
            "DependsOn": self.DependsOn,
            "RelatedTo": self.RelatedTo,
            "Notes": self.Notes,
        }


@dataclass
class Check_Report:
    check_id: str = ""
    check_metadata: CheckMetadata = field(default_factory=CheckMetadata)
    resource: Any = None
    status: str = "UNKNOWN"
    status_extended: str = ""
    resource_id: str = ""

    def as_dict(self):
        return {
            "check_id": self.check_id,
            "status": self.status,
            "status_extended": self.status_extended,
            "resource_id": self.resource_id,
            "severity": self.check_metadata.Severity,
            "service": self.check_metadata.ServiceName,
        }


@dataclass
class Check_Report_AWS(Check_Report):
    resource_arn: str = ""
    region: str = ""

    def as_dict(self):
        data = super().as_dict()
        data.update({
            "resource_arn": self.resource_arn,
            "region": self.region,
        })
        return data


class Check(ABC):
    def __init__(self):
        self.CheckID = self.__class__.__name__
        self.service_name = ""
        self.metadata_file = None
        self._metadata = CheckMetadata()
        self._load_metadata()

    def _load_metadata(self):
        check_dir = os.path.dirname(self.__class__.__module__.replace(".", "/"))
        possible_paths = [
            os.path.join(check_dir, f"{self.CheckID}.metadata.json"),
            os.path.join(check_dir, "..", f"{self.CheckID}.metadata.json"),
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                self._metadata = CheckMetadata.from_file(path)
                self.metadata_file = path
                break
        
        if not self._metadata.CheckID:
            self._metadata.CheckID = self.CheckID
            if not self._metadata.Severity:
                self._metadata.Severity = "medium"
            if not self._metadata.ServiceName:
                self._metadata.ServiceName = getattr(self, "service_name", "")
    
    def metadata(self):
        return self._metadata

    @abstractmethod
    def execute(self):
        pass

    def __repr__(self):
        return f"<Check {self.CheckID}>"


class Finding:
    def __init__(self, check_id, resource_id, status, message, severity="medium", region="", arn=""):
        self.check_id = check_id
        self.resource_id = resource_id
        self.status = status
        self.message = message
        self.severity = severity
        self.region = region
        self.arn = arn

    def to_dict(self):
        return {
            "check_id": self.check_id,
            "resource_id": self.resource_id,
            "status": self.status,
            "message": self.message,
            "severity": self.severity,
            "region": self.region,
            "arn": self.arn,
        }


def load_check_metadata(check_id: str, module_path: str) -> CheckMetadata:
    check_dir = os.path.dirname(module_path)
    
    possible_paths = [
        os.path.join(check_dir, f"{check_id}.metadata.json"),
    ]
    
    for path in possible_paths:
        if os.path.exists(path):
            return CheckMetadata.from_file(path)
    
    return CheckMetadata()


def get_service_checks(service_name: str):
    try:
        module_name = f"providers.aws.services.{service_name}.{service_name}_client"
        __import__(module_name)
        module = sys.modules[module_name]
        return getattr(module, f"{service_name}_client", None)
    except (ImportError, AttributeError):
        return None