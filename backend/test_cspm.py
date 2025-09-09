#!/usr/bin/env python3
"""
Test script for Anbu CSPM Backend
Demonstrates the cloud security scanning capabilities
"""

import asyncio
import json
from core.scanner_manager import ScannerManager
from core.config import validate_cloud_credentials

async def test_cspm_backend():
    """Test the CSPM backend functionality"""
    print("🔍 Anbu CSPM Backend Test")
    print("=" * 50)
    
    # Check cloud provider credentials
    print("\n1. Checking cloud provider credentials...")
    credentials = validate_cloud_credentials()
    
    for provider, is_configured in credentials.items():
        status = "✅ Configured" if is_configured else "❌ Not configured"
        print(f"   {provider.upper()}: {status}")
    
    if not any(credentials.values()):
        print("\n⚠️  No cloud providers configured!")
        print("   To test with real AWS/GCP resources:")
        print("   - Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY")
        print("   - Or set GCP_PROJECT_ID and GOOGLE_APPLICATION_CREDENTIALS")
        print("   - Copy env.example to .env and configure")
        return
    
    # Initialize scanner manager
    print("\n2. Initializing scanner manager...")
    scanner_manager = ScannerManager()
    scanner_manager.register_all_scanners()
    
    print(f"   Registered {len(scanner_manager.scanners)} scanners:")
    for scanner in scanner_manager.scanners:
        print(f"   - {scanner.get_scanner_name()} ({scanner.provider.value})")
    
    # Run a test scan
    print("\n3. Running security scan...")
    try:
        scan_results = await scanner_manager.run_all_scans()
        
        print(f"   ✅ Scan completed in {scan_results.get('duration_seconds', 0):.2f}s")
        print(f"   📊 Total findings: {scan_results.get('total_findings', 0)}")
        
        # Show severity breakdown
        severity_breakdown = scan_results.get('severity_breakdown', {})
        if severity_breakdown:
            print("   📈 Severity breakdown:")
            for severity, count in severity_breakdown.items():
                print(f"      {severity.upper()}: {count}")
        
        # Show sample findings
        if scanner_manager.findings:
            print("\n4. Sample security findings:")
            for i, finding in enumerate(scanner_manager.findings[:3]):  # Show first 3
                print(f"\n   Finding #{i+1}:")
                print(f"   Provider: {finding.provider.value if finding.provider else 'Unknown'}")
                print(f"   Resource: {finding.resource_type} - {finding.resource_name or finding.resource_id}")
                print(f"   Issue: {finding.issue}")
                print(f"   Severity: {finding.severity.value if finding.severity else 'Unknown'}")
                print(f"   Recommendation: {finding.recommendation}")
                
                if finding.terraform_patch:
                    print(f"   Terraform Patch Available: ✅")
        
        # Show scanner results
        print("\n5. Scanner results:")
        for scanner_name, result in scan_results.get('scanners', {}).items():
            status = "✅ Success" if not result.get('error') else f"❌ Error: {result.get('error')}"
            print(f"   {scanner_name}: {status} ({result.get('findings_count', 0)} findings)")
        
        # Export findings
        if scanner_manager.findings:
            print("\n6. Exporting findings...")
            json_export = scanner_manager.export_findings_json()
            print(f"   ✅ Exported {len(scanner_manager.findings)} findings as JSON")
            print(f"   Export size: {len(json_export)} characters")
        
    except Exception as e:
        print(f"   ❌ Scan failed: {str(e)}")
        print("   This is expected if AWS/GCP credentials are not properly configured")
    
    print("\n" + "=" * 50)
    print("🎯 CSPM Backend Test Complete!")
    print("\nNext steps:")
    print("1. Configure cloud provider credentials")
    print("2. Run: uvicorn main:app --reload")
    print("3. Visit: http://localhost:8000/docs")
    print("4. Test the /scan endpoint")

if __name__ == "__main__":
    asyncio.run(test_cspm_backend())
