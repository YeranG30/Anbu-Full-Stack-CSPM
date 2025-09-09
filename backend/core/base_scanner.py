"""
Base scanner interface for CSPM cloud security scanning
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from datetime import datetime
from enum import Enum
from dataclasses import dataclass
from core.config import CloudProvider, ScanSeverity

@dataclass
class SecurityFinding:
    """Standardized security finding across all cloud providers"""
    id: Optional[str] = None
    provider: CloudProvider = None
    resource_type: str = ""
    resource_id: str = ""
    resource_name: str = ""
    issue: str = ""
    severity: ScanSeverity = ScanSeverity.MEDIUM
    description: str = ""
    recommendation: str = ""
    terraform_patch: Optional[str] = None
    raw_policy: Optional[Dict[str, Any]] = None
    detected_at: datetime = None
    region: Optional[str] = None
    account_id: Optional[str] = None
    
    def __post_init__(self):
        if self.detected_at is None:
            self.detected_at = datetime.utcnow()

class BaseScanner(ABC):
    """Abstract base class for all cloud security scanners"""
    
    def __init__(self, provider: CloudProvider, region: Optional[str] = None):
        self.provider = provider
        self.region = region
        self.findings: List[SecurityFinding] = []
        self.scan_start_time: Optional[datetime] = None
        self.scan_end_time: Optional[datetime] = None
    
    @abstractmethod
    async def scan(self) -> List[SecurityFinding]:
        """Perform the security scan and return findings"""
        pass
    
    @abstractmethod
    def get_scanner_name(self) -> str:
        """Return human-readable scanner name"""
        pass
    
    def add_finding(self, finding: SecurityFinding) -> None:
        """Add a finding to the scanner's results"""
        finding.provider = self.provider
        finding.region = self.region
        self.findings.append(finding)
    
    def get_scan_summary(self) -> Dict[str, Any]:
        """Get summary statistics for the scan"""
        if not self.scan_start_time or not self.scan_end_time:
            return {"status": "incomplete"}
        
        duration = (self.scan_end_time - self.scan_start_time).total_seconds()
        
        severity_counts = {}
        for severity in ScanSeverity:
            severity_counts[severity.value] = sum(
                1 for f in self.findings if f.severity == severity
            )
        
        return {
            "scanner": self.get_scanner_name(),
            "provider": self.provider.value,
            "region": self.region,
            "total_findings": len(self.findings),
            "severity_breakdown": severity_counts,
            "duration_seconds": duration,
            "scan_start": self.scan_start_time.isoformat(),
            "scan_end": self.scan_end_time.isoformat()
        }
    
    def start_scan(self) -> None:
        """Mark the start of a scan"""
        self.scan_start_time = datetime.utcnow()
        self.findings.clear()
    
    def end_scan(self) -> None:
        """Mark the end of a scan"""
        self.scan_end_time = datetime.utcnow()
    
    def __str__(self) -> str:
        return f"{self.get_scanner_name()} ({self.provider.value})"
