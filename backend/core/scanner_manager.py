"""
Scanner Manager - Orchestrates all cloud security scanners
"""

import asyncio
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

from core.base_scanner import BaseScanner, SecurityFinding
from core.config import CloudProvider, validate_cloud_credentials
from scanner.iam.aws_iam_scanner import AWSIAMScanner
from scanner.exposure.aws_s3_scanner import AWSS3Scanner

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ScannerManager:
    """Manages and orchestrates all cloud security scanners"""
    
    def __init__(self):
        self.scanners: List[BaseScanner] = []
        self.findings: List[SecurityFinding] = []
        self.scan_results: Dict[str, Any] = {}
        self.max_concurrent_scans = 5
        
    def register_scanner(self, scanner: BaseScanner) -> None:
        """Register a scanner with the manager"""
        self.scanners.append(scanner)
        logger.info(f"Registered scanner: {scanner}")
    
    def register_all_scanners(self) -> None:
        """Register all available scanners based on cloud provider configuration"""
        credentials = validate_cloud_credentials()
        
        # Register AWS scanners
        if credentials.get(CloudProvider.AWS, False):
            logger.info("Registering AWS scanners...")
            self.register_scanner(AWSIAMScanner(region="us-east-1"))
            self.register_scanner(AWSS3Scanner(region="us-east-1"))
            
            # Add more regions if needed
            additional_regions = ["us-west-2", "eu-west-1", "ap-southeast-1"]
            for region in additional_regions:
                self.register_scanner(AWSIAMScanner(region=region))
                self.register_scanner(AWSS3Scanner(region=region))
        else:
            logger.warning("AWS credentials not configured - skipping AWS scanners")
        
        # Register GCP scanners (when implemented)
        if credentials.get(CloudProvider.GCP, False):
            logger.info("GCP scanners not yet implemented")
        else:
            logger.warning("GCP credentials not configured - skipping GCP scanners")
        
        logger.info(f"Total scanners registered: {len(self.scanners)}")
    
    async def run_all_scans(self) -> Dict[str, Any]:
        """Run all registered scanners concurrently"""
        if not self.scanners:
            logger.warning("No scanners registered")
            return {"error": "No scanners registered"}
        
        logger.info(f"Starting scan with {len(self.scanners)} scanners")
        start_time = datetime.utcnow()
        
        # Run scanners concurrently with limited concurrency
        semaphore = asyncio.Semaphore(self.max_concurrent_scans)
        
        async def run_scanner_with_semaphore(scanner: BaseScanner):
            async with semaphore:
                try:
                    logger.info(f"Starting scan: {scanner}")
                    findings = await scanner.scan()
                    logger.info(f"Completed scan: {scanner} - {len(findings)} findings")
                    return scanner, findings, None
                except Exception as e:
                    logger.error(f"Scanner {scanner} failed: {str(e)}")
                    return scanner, [], str(e)
        
        # Execute all scanners concurrently
        tasks = [run_scanner_with_semaphore(scanner) for scanner in self.scanners]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        self.findings.clear()
        self.scan_results = {
            "scan_id": f"scan_{int(datetime.utcnow().timestamp())}",
            "start_time": start_time.isoformat(),
            "end_time": datetime.utcnow().isoformat(),
            "scanners": {},
            "total_findings": 0,
            "severity_breakdown": {},
            "errors": []
        }
        
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Scanner task failed: {str(result)}")
                self.scan_results["errors"].append(str(result))
                continue
            
            scanner, findings, error = result
            
            # Add findings to collection
            self.findings.extend(findings)
            
            # Record scanner results
            scanner_name = scanner.get_scanner_name()
            self.scan_results["scanners"][scanner_name] = {
                "provider": scanner.provider.value,
                "region": scanner.region,
                "findings_count": len(findings),
                "summary": scanner.get_scan_summary(),
                "error": error
            }
            
            if error:
                self.scan_results["errors"].append(f"{scanner_name}: {error}")
        
        # Calculate totals and severity breakdown
        self.scan_results["total_findings"] = len(self.findings)
        
        severity_counts = {}
        for finding in self.findings:
            severity = finding.severity.value
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        self.scan_results["severity_breakdown"] = severity_counts
        
        duration = (datetime.utcnow() - start_time).total_seconds()
        self.scan_results["duration_seconds"] = duration
        
        logger.info(f"Scan completed in {duration:.2f}s - {len(self.findings)} total findings")
        
        return self.scan_results
    
    async def run_scanner_by_name(self, scanner_name: str) -> List[SecurityFinding]:
        """Run a specific scanner by name"""
        scanner = next((s for s in self.scanners if s.get_scanner_name() == scanner_name), None)
        
        if not scanner:
            raise ValueError(f"Scanner '{scanner_name}' not found")
        
        logger.info(f"Running single scanner: {scanner}")
        findings = await scanner.scan()
        logger.info(f"Scanner {scanner} completed - {len(findings)} findings")
        
        return findings
    
    async def run_scanner_by_provider(self, provider: CloudProvider) -> List[SecurityFinding]:
        """Run all scanners for a specific cloud provider"""
        provider_scanners = [s for s in self.scanners if s.provider == provider]
        
        if not provider_scanners:
            logger.warning(f"No scanners found for provider: {provider}")
            return []
        
        logger.info(f"Running {len(provider_scanners)} scanners for {provider}")
        
        # Run scanners concurrently
        tasks = [scanner.scan() for scanner in provider_scanners]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Collect all findings
        all_findings = []
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Provider scanner failed: {str(result)}")
                continue
            
            all_findings.extend(result)
        
        logger.info(f"Provider {provider} scan completed - {len(all_findings)} findings")
        return all_findings
    
    def get_findings_by_severity(self, severity: str) -> List[SecurityFinding]:
        """Get findings filtered by severity"""
        return [f for f in self.findings if f.severity.value == severity]
    
    def get_findings_by_provider(self, provider: CloudProvider) -> List[SecurityFinding]:
        """Get findings filtered by cloud provider"""
        return [f for f in self.findings if f.provider == provider]
    
    def get_findings_by_resource_type(self, resource_type: str) -> List[SecurityFinding]:
        """Get findings filtered by resource type"""
        return [f for f in self.findings if f.resource_type == resource_type]
    
    def get_scan_summary(self) -> Dict[str, Any]:
        """Get overall scan summary"""
        if not self.scan_results:
            return {"status": "no_scans_run"}
        
        return {
            "scan_id": self.scan_results.get("scan_id"),
            "total_findings": len(self.findings),
            "severity_breakdown": self.scan_results.get("severity_breakdown", {}),
            "scanners_run": len(self.scan_results.get("scanners", {})),
            "duration_seconds": self.scan_results.get("duration_seconds", 0),
            "errors": self.scan_results.get("errors", [])
        }
    
    def export_findings_json(self) -> str:
        """Export findings as JSON string"""
        import json
        
        findings_data = []
        for finding in self.findings:
            finding_dict = {
                "id": finding.id,
                "provider": finding.provider.value if finding.provider else None,
                "resource_type": finding.resource_type,
                "resource_id": finding.resource_id,
                "resource_name": finding.resource_name,
                "issue": finding.issue,
                "severity": finding.severity.value if finding.severity else None,
                "description": finding.description,
                "recommendation": finding.recommendation,
                "terraform_patch": finding.terraform_patch,
                "region": finding.region,
                "account_id": finding.account_id,
                "detected_at": finding.detected_at.isoformat() if finding.detected_at else None
            }
            findings_data.append(finding_dict)
        
        return json.dumps(findings_data, indent=2)
    
    def clear_findings(self) -> None:
        """Clear all findings and scan results"""
        self.findings.clear()
        self.scan_results = {}
        logger.info("Cleared all findings and scan results")
