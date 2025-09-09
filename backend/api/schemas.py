from pydantic import BaseModel
from datetime import datetime
from typing import Optional, List, Dict, Any

# using pydantic to allow clean coversion from sql to json for react front end

class FindingOut(BaseModel):
    id: int
    provider: str
    resource_type: str
    resource_id: str
    issue: str
    severity: str
    recommendation: Optional[str]
    terraform_patch: Optional[str]
    timestamp: datetime

    class Config:
        orm_mode = True  # allows SQLAlchemy  to Pydantic conversion

class ScanRequest(BaseModel):
    """Request model for starting a scan"""
    providers: Optional[List[str]] = None  # ["aws", "gcp"]
    regions: Optional[List[str]] = None    # ["us-east-1", "us-west-2"]
    scanner_types: Optional[List[str]] = None  # ["iam", "exposure"]
    
class ScanResponse(BaseModel):
    """Response model for scan operations"""
    status: str
    message: str
    scan_id: Optional[str] = None

class ScanStatus(BaseModel):
    """Model for scan status and summary"""
    scan_id: Optional[str] = None
    total_findings: int
    severity_breakdown: Dict[str, int]
    scanners_run: int
    duration_seconds: float
    errors: List[str]

class ScannerInfo(BaseModel):
    """Model for scanner information"""
    name: str
    provider: str
    region: str

class ScanFindingsResponse(BaseModel):
    """Response model for scan findings"""
    findings: List[Dict[str, Any]]
    total: int
    summary: ScanStatus
