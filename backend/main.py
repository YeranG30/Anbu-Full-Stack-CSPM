from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from db.database import SessionLocal, init_db
from db import models
from db.models import Finding
from api.schemas import FindingOut, ScanRequest, ScanResponse
from core.scanner_manager import ScannerManager
from core.config import validate_cloud_credentials
from typing import List, Dict, Any
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Anbu CSPM API",
    description="Cloud Security Posture Manager API",
    version="1.0.0"
)

# Initialize database
init_db()

# Initialize scanner manager
scanner_manager = ScannerManager()
scanner_manager.register_all_scanners()

def seed_test_data():
    db = SessionLocal()
    if db.query(Finding).count() == 0:
        test = Finding(
            provider="gcp",
            resource_type="iam_role",
            resource_id="projects/foo/roles/admin",
            issue="Wildcard permission",
            severity="high",
            recommendation="Replace * with specific permissions",
            terraform_patch='resource "google_project_iam_custom_role" {}'
        )
        db.add(test)
        db.commit()
    db.close()

seed_test_data()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.get("/health")
def health_check():
    """Health check endpoint"""
    credentials = validate_cloud_credentials()
    return {
        "status": "ok",
        "cloud_providers": {
            "aws": credentials.get("aws", False),
            "gcp": credentials.get("gcp", False)
        },
        "scanners_registered": len(scanner_manager.scanners)
    }

@app.get("/findings", response_model=List[FindingOut])
def read_findings(db: Session = Depends(get_db)):
    """Get all security findings from database"""
    findings = db.query(models.Finding).all()
    return findings

@app.post("/scan", response_model=ScanResponse)
async def start_scan(background_tasks: BackgroundTasks, scan_request: ScanRequest = None):
    """Start a new security scan"""
    try:
        logger.info("Starting security scan...")
        
        # Run scan in background
        background_tasks.add_task(run_scan_and_save)
        
        return {
            "status": "scan_started",
            "message": "Security scan started in background",
            "scan_id": f"scan_{int(__import__('time').time())}"
        }
    except Exception as e:
        logger.error(f"Failed to start scan: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to start scan: {str(e)}")

async def run_scan_and_save():
    """Run scan and save results to database"""
    try:
        # Run all scanners
        scan_results = await scanner_manager.run_all_scans()
        
        # Save findings to database
        db = SessionLocal()
        try:
            for finding in scanner_manager.findings:
                db_finding = Finding(
                    provider=finding.provider.value if finding.provider else "unknown",
                    resource_type=finding.resource_type,
                    resource_id=finding.resource_id,
                    issue=finding.issue,
                    severity=finding.severity.value if finding.severity else "medium",
                    recommendation=finding.recommendation,
                    terraform_patch=finding.terraform_patch
                )
                db.add(db_finding)
            
            db.commit()
            logger.info(f"Saved {len(scanner_manager.findings)} findings to database")
        finally:
            db.close()
            
    except Exception as e:
        logger.error(f"Error during scan and save: {str(e)}")

@app.get("/scan/status")
def get_scan_status():
    """Get current scan status and summary"""
    summary = scanner_manager.get_scan_summary()
    return summary

@app.get("/scan/findings")
def get_scan_findings():
    """Get findings from the last scan"""
    if not scanner_manager.findings:
        return {"findings": [], "message": "No scan results available"}
    
    findings_data = []
    for finding in scanner_manager.findings:
        findings_data.append({
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
            "detected_at": finding.detected_at.isoformat() if finding.detected_at else None
        })
    
    return {
        "findings": findings_data,
        "total": len(findings_data),
        "summary": scanner_manager.get_scan_summary()
    }

@app.get("/scan/export")
def export_findings():
    """Export findings as JSON"""
    if not scanner_manager.findings:
        raise HTTPException(status_code=404, detail="No findings to export")
    
    return {
        "findings": scanner_manager.export_findings_json(),
        "exported_at": __import__('datetime').datetime.utcnow().isoformat()
    }

@app.get("/scanners")
def list_scanners():
    """List all registered scanners"""
    scanners = []
    for scanner in scanner_manager.scanners:
        scanners.append({
            "name": scanner.get_scanner_name(),
            "provider": scanner.provider.value,
            "region": scanner.region
        })
    
    return {
        "scanners": scanners,
        "total": len(scanners)
    }