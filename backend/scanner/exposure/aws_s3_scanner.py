"""
AWS S3 Security Scanner
Detects public exposure, overly permissive policies, and data leakage risks
"""

import boto3
import json
from typing import List, Dict, Any, Optional
from datetime import datetime
from botocore.exceptions import ClientError, NoCredentialsError

from core.base_scanner import BaseScanner, SecurityFinding
from core.config import CloudProvider, ScanSeverity, get_aws_config

class AWSS3Scanner(BaseScanner):
    """Scanner for AWS S3 security issues and public exposure"""
    
    def __init__(self, region: str = "us-east-1"):
        super().__init__(CloudProvider.AWS, region)
        self.s3_client = None
        self.s3control_client = None
        self.account_id = None
    
    async def scan(self) -> List[SecurityFinding]:
        """Perform comprehensive AWS S3 security scan"""
        self.start_scan()
        
        try:
            # Initialize AWS clients
            await self._initialize_clients()
            
            # Get account information
            await self._get_account_info()
            
            # Run all S3 security checks
            await self._scan_buckets()
            
        except NoCredentialsError:
            self.add_finding(SecurityFinding(
                resource_type="aws_credentials",
                resource_id="aws_account",
                issue="AWS credentials not configured",
                severity=ScanSeverity.CRITICAL,
                description="Unable to authenticate with AWS. Please configure AWS credentials.",
                recommendation="Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables or configure AWS CLI"
            ))
        except Exception as e:
            self.add_finding(SecurityFinding(
                resource_type="aws_s3_scan",
                resource_id="aws_account",
                issue="S3 scan failed",
                severity=ScanSeverity.HIGH,
                description=f"Error during S3 scanning: {str(e)}",
                recommendation="Check AWS permissions and network connectivity"
            ))
        finally:
            self.end_scan()
        
        return self.findings
    
    async def _initialize_clients(self):
        """Initialize AWS clients with proper configuration"""
        config = get_aws_config()
        self.s3_client = boto3.client('s3', **config)
        self.s3control_client = boto3.client('s3control', **config)
    
    async def _get_account_info(self):
        """Get AWS account information"""
        try:
            sts_client = boto3.client('sts', **get_aws_config())
            response = sts_client.get_caller_identity()
            self.account_id = response.get('Account')
        except ClientError as e:
            self.add_finding(SecurityFinding(
                resource_type="aws_account",
                resource_id="unknown",
                issue="Cannot retrieve account information",
                severity=ScanSeverity.HIGH,
                description=f"Failed to get AWS account ID: {str(e)}",
                recommendation="Ensure IAM credentials have sts:GetCallerIdentity permission"
            ))
    
    async def _scan_buckets(self):
        """Scan all S3 buckets for security issues"""
        try:
            response = self.s3_client.list_buckets()
            
            for bucket in response['Buckets']:
                bucket_name = bucket['Name']
                await self._analyze_bucket(bucket_name)
                
        except ClientError as e:
            self.add_finding(SecurityFinding(
                resource_type="aws_s3_buckets",
                resource_id="all_buckets",
                issue="Cannot list S3 buckets",
                severity=ScanSeverity.HIGH,
                description=f"Failed to list S3 buckets: {str(e)}",
                recommendation="Ensure IAM credentials have s3:ListAllMyBuckets permission"
            ))
    
    async def _analyze_bucket(self, bucket_name: str):
        """Analyze individual S3 bucket for security issues"""
        bucket_arn = f"arn:aws:s3:::{bucket_name}"
        
        # Check for public access
        public_access = await self._check_public_access(bucket_name)
        if public_access['is_public']:
            self.add_finding(SecurityFinding(
                resource_type="aws_s3_bucket",
                resource_id=bucket_arn,
                resource_name=bucket_name,
                issue="S3 bucket is publicly accessible",
                severity=ScanSeverity.CRITICAL,
                description=f"S3 bucket '{bucket_name}' is publicly accessible: {public_access['reason']}",
                recommendation="Remove public access and implement proper access controls",
                terraform_patch=self._generate_bucket_public_access_patch(bucket_name)
            ))
        
        # Check bucket policy for overly permissive access
        policy_issues = await self._check_bucket_policy(bucket_name)
        for issue in policy_issues:
            self.add_finding(SecurityFinding(
                resource_type="aws_s3_bucket",
                resource_id=bucket_arn,
                resource_name=bucket_name,
                issue=issue['issue'],
                severity=issue['severity'],
                description=issue['description'],
                recommendation=issue['recommendation'],
                terraform_patch=issue.get('terraform_patch')
            ))
        
        # Check for encryption
        encryption_issues = await self._check_encryption(bucket_name)
        for issue in encryption_issues:
            self.add_finding(SecurityFinding(
                resource_type="aws_s3_bucket",
                resource_id=bucket_arn,
                resource_name=bucket_name,
                issue=issue['issue'],
                severity=issue['severity'],
                description=issue['description'],
                recommendation=issue['recommendation'],
                terraform_patch=issue.get('terraform_patch')
            ))
        
        # Check for versioning
        versioning_issues = await self._check_versioning(bucket_name)
        for issue in versioning_issues:
            self.add_finding(SecurityFinding(
                resource_type="aws_s3_bucket",
                resource_id=bucket_arn,
                resource_name=bucket_name,
                issue=issue['issue'],
                severity=issue['severity'],
                description=issue['description'],
                recommendation=issue['recommendation'],
                terraform_patch=issue.get('terraform_patch')
            ))
    
    async def _check_public_access(self, bucket_name: str) -> Dict[str, Any]:
        """Check if bucket has public access"""
        try:
            # Check public access block settings
            try:
                public_access_block = self.s3_client.get_public_access_block(Bucket=bucket_name)
                block_settings = public_access_block['PublicAccessBlockConfiguration']
                
                # If any public access is allowed, it's a security risk
                if not all([
                    block_settings.get('BlockPublicAcls', False),
                    block_settings.get('IgnorePublicAcls', False),
                    block_settings.get('BlockPublicPolicy', False),
                    block_settings.get('RestrictPublicBuckets', False)
                ]):
                    return {
                        'is_public': True,
                        'reason': 'Public access block not fully configured'
                    }
            except ClientError:
                # No public access block configured - potential risk
                pass
            
            # Check bucket ACL
            try:
                acl = self.s3_client.get_bucket_acl(Bucket=bucket_name)
                for grant in acl.get('Grants', []):
                    grantee = grant.get('Grantee', {})
                    if grantee.get('Type') == 'Group' and grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                        return {
                            'is_public': True,
                            'reason': 'Bucket ACL allows public read access'
                        }
            except ClientError:
                pass
            
            # Check bucket policy for public access
            try:
                policy = self.s3_client.get_bucket_policy(Bucket=bucket_name)
                policy_doc = json.loads(policy['Policy'])
                
                for statement in policy_doc.get('Statement', []):
                    if statement.get('Effect') == 'Allow':
                        principal = statement.get('Principal', {})
                        
                        # Check for wildcard principal
                        if principal == '*' or (isinstance(principal, dict) and '*' in str(principal)):
                            return {
                                'is_public': True,
                                'reason': 'Bucket policy allows wildcard principal access'
                            }
                        
                        # Check for public access in principal
                        if isinstance(principal, dict) and 'AWS' in principal:
                            aws_principals = principal['AWS']
                            if isinstance(aws_principals, str):
                                aws_principals = [aws_principals]
                            
                            for aws_principal in aws_principals:
                                if aws_principal == '*':
                                    return {
                                        'is_public': True,
                                        'reason': 'Bucket policy allows wildcard AWS principal'
                                    }
            
            except ClientError:
                pass
            
            return {'is_public': False, 'reason': 'No public access detected'}
            
        except Exception as e:
            return {'is_public': False, 'reason': f'Error checking public access: {str(e)}'}
    
    async def _check_bucket_policy(self, bucket_name: str) -> List[Dict[str, Any]]:
        """Check bucket policy for security issues"""
        issues = []
        
        try:
            policy = self.s3_client.get_bucket_policy(Bucket=bucket_name)
            policy_doc = json.loads(policy['Policy'])
            
            for statement in policy_doc.get('Statement', []):
                if statement.get('Effect') == 'Allow':
                    # Check for overly broad actions
                    actions = statement.get('Action', [])
                    if isinstance(actions, str):
                        actions = [actions]
                    
                    if '*' in actions or 's3:*' in actions:
                        issues.append({
                            'issue': 'Bucket policy allows wildcard actions',
                            'severity': ScanSeverity.HIGH,
                            'description': f"Bucket policy allows wildcard S3 actions",
                            'recommendation': 'Replace wildcard actions with specific permissions',
                            'terraform_patch': self._generate_bucket_policy_patch(bucket_name, "Restrict actions")
                        })
                    
                    # Check for 0.0.0.0/0 access
                    condition = statement.get('Condition', {})
                    if self._has_worldwide_access_condition(condition):
                        issues.append({
                            'issue': 'Bucket policy allows worldwide access',
                            'severity': ScanSeverity.CRITICAL,
                            'description': f"Bucket policy allows access from 0.0.0.0/0",
                            'recommendation': 'Restrict access to specific IP ranges or remove condition',
                            'terraform_patch': self._generate_bucket_policy_patch(bucket_name, "Restrict IP access")
                        })
        
        except ClientError:
            # No bucket policy - not necessarily an issue
            pass
        
        return issues
    
    def _has_worldwide_access_condition(self, condition: Dict[str, Any]) -> bool:
        """Check if condition allows worldwide access"""
        for key, value in condition.items():
            if isinstance(value, dict):
                for sub_key, sub_value in value.items():
                    if isinstance(sub_value, dict) and 'aws:SourceIp' in sub_value:
                        ip_values = sub_value['aws:SourceIp']
                        if isinstance(ip_values, str):
                            ip_values = [ip_values]
                        
                        for ip_value in ip_values:
                            if '0.0.0.0/0' in ip_value:
                                return True
        
        return False
    
    async def _check_encryption(self, bucket_name: str) -> List[Dict[str, Any]]:
        """Check bucket encryption configuration"""
        issues = []
        
        try:
            encryption = self.s3_client.get_bucket_encryption(Bucket=bucket_name)
            # Encryption is configured - good
        except ClientError:
            # No encryption configured
            issues.append({
                'issue': 'S3 bucket encryption not enabled',
                'severity': ScanSeverity.HIGH,
                'description': f"S3 bucket '{bucket_name}' does not have encryption enabled",
                'recommendation': 'Enable server-side encryption for all S3 buckets',
                'terraform_patch': self._generate_encryption_patch(bucket_name)
            })
        
        return issues
    
    async def _check_versioning(self, bucket_name: str) -> List[Dict[str, Any]]:
        """Check bucket versioning configuration"""
        issues = []
        
        try:
            versioning = self.s3_client.get_bucket_versioning(Bucket=bucket_name)
            if versioning.get('Status') != 'Enabled':
                issues.append({
                    'issue': 'S3 bucket versioning not enabled',
                    'severity': ScanSeverity.MEDIUM,
                    'description': f"S3 bucket '{bucket_name}' does not have versioning enabled",
                    'recommendation': 'Enable versioning to protect against accidental deletion',
                    'terraform_patch': self._generate_versioning_patch(bucket_name)
                })
        except ClientError:
            issues.append({
                'issue': 'Cannot check S3 bucket versioning',
                'severity': ScanSeverity.LOW,
                'description': f"Cannot retrieve versioning status for bucket '{bucket_name}'",
                'recommendation': 'Verify bucket permissions and enable versioning'
            })
        
        return issues
    
    def _generate_bucket_public_access_patch(self, bucket_name: str) -> str:
        """Generate Terraform patch for bucket public access"""
        return f'''
# Terraform patch for S3 bucket public access: {bucket_name}
# Block all public access

resource "aws_s3_bucket" "{bucket_name.replace('-', '_')}" {{
  bucket = "{bucket_name}"
}}

resource "aws_s3_bucket_public_access_block" "{bucket_name.replace('-', '_')}" {{
  bucket = aws_s3_bucket.{bucket_name.replace('-', '_')}.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}}
'''
    
    def _generate_bucket_policy_patch(self, bucket_name: str, description: str) -> str:
        """Generate Terraform patch for bucket policy"""
        return f'''
# Terraform patch for S3 bucket policy: {bucket_name}
# {description}

resource "aws_s3_bucket_policy" "{bucket_name.replace('-', '_')}" {{
  bucket = aws_s3_bucket.{bucket_name.replace('-', '_')}.id

  policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [
      {{
        Sid    = "RestrictAccess"
        Effect = "Allow"
        Principal = {{
          # TODO: Replace with specific principals
          # Avoid wildcards and 0.0.0.0/0
        }}
        Action = [
          # TODO: Replace with specific actions
          # Avoid s3:* wildcard
        ]
        Resource = [
          "arn:aws:s3:::{bucket_name}",
          "arn:aws:s3:::{bucket_name}/*"
        ]
      }}
    ]
  }})
}}
'''
    
    def _generate_encryption_patch(self, bucket_name: str) -> str:
        """Generate Terraform patch for bucket encryption"""
        return f'''
# Terraform patch for S3 bucket encryption: {bucket_name}
# Enable server-side encryption

resource "aws_s3_bucket_server_side_encryption_configuration" "{bucket_name.replace('-', '_')}" {{
  bucket = aws_s3_bucket.{bucket_name.replace('-', '_')}.id

  rule {{
    apply_server_side_encryption_by_default {{
      sse_algorithm = "AES256"
    }}
  }}
}}
'''
    
    def _generate_versioning_patch(self, bucket_name: str) -> str:
        """Generate Terraform patch for bucket versioning"""
        return f'''
# Terraform patch for S3 bucket versioning: {bucket_name}
# Enable versioning

resource "aws_s3_bucket_versioning" "{bucket_name.replace('-', '_')}" {{
  bucket = aws_s3_bucket.{bucket_name.replace('-', '_')}.id
  versioning_configuration {{
    status = "Enabled"
  }}
}}
'''
    
    def get_scanner_name(self) -> str:
        return "AWS S3 Security Scanner"
