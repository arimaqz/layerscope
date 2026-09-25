from pydantic import BaseModel, ConfigDict, Field


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    image_ids: list[int] = Field(min_length=1, max_length=500)


class BulkScanDeleteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scan_ids: list[int] = Field(min_length=1, max_length=500)


class BulkImageDeleteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    image_ids: list[int] = Field(min_length=1, max_length=500)


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")
    id: int
    target: str
    vulnerability_id: str
    package_name: str
    installed_version: str
    fixed_version: str
    severity: str
    title: str
    description: str
    primary_url: str
