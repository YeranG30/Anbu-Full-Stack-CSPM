"""
AWS IAM Security Scanner
Detects IAM misconfigurations, overprivileged roles, and security issues
"""

import boto3
import json
from typing import List, Dict, Any, Optional
from datetime import datetime
from botocore.exceptions import ClientError, NoCredentialsError

from core.base_scanner import BaseScanner, SecurityFinding
from core.config import CloudProvider, ScanSeverity, get_aws_config

class AWSIAMScanner(BaseScanner):
    """Scanner for AWS IAM security issues"""
    
    def __init__(self, region: str = "us-east-1"):
        super().__init__(CloudProvider.AWS, region)
        self.iam_client = None
        self.sts_client = None
        self.account_id = None
    
    async def scan(self) -> List[SecurityFinding]:
        """Perform comprehensive AWS IAM security scan"""
        self.start_scan()
        
        try:
            # Initialize AWS clients
            await self._initialize_clients()
            
            # Get account information
            await self._get_account_info()
            
            # Run all IAM security checks
            await self._scan_roles()
            await self._scan_users()
            await self._scan_policies()
            await self._scan_groups()
            await self._scan_access_keys()
            
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
                resource_type="aws_iam_scan",
                resource_id="aws_account",
                issue="IAM scan failed",
                severity=ScanSeverity.HIGH,
                description=f"Error during IAM scanning: {str(e)}",
                recommendation="Check AWS permissions and network connectivity"
            ))
        finally:
            self.end_scan()
        
        return self.findings
    
    async def _initialize_clients(self):
        """Initialize AWS clients with proper configuration"""
        config = get_aws_config()
        self.iam_client = boto3.client('iam', **config)
        self.sts_client = boto3.client('sts', **config)
    
    async def _get_account_info(self):
        """Get AWS account information"""
        try:
            response = self.sts_client.get_caller_identity()
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
    
    async def _scan_roles(self):
        """Scan IAM roles for security issues"""
        try:
            paginator = self.iam_client.get_paginator('list_roles')
            
            for page in paginator.paginate():
                for role in page['Roles']:
                    await self._analyze_role(role)
                    
        except ClientError as e:
            self.add_finding(SecurityFinding(
                resource_type="aws_iam_roles",
                resource_id="all_roles",
                issue="Cannot list IAM roles",
                severity=ScanSeverity.HIGH,
                description=f"Failed to list IAM roles: {str(e)}",
                recommendation="Ensure IAM credentials have iam:ListRoles permission"
            ))
    
    async def _analyze_role(self, role: Dict[str, Any]):
        """Analyze individual IAM role for security issues"""
        role_name = role['RoleName']
        role_arn = role['Arn']
        
        # Check for admin access
        if await self._has_admin_access(role):
            self.add_finding(SecurityFinding(
                resource_type="aws_iam_role",
                resource_id=role_arn,
                resource_name=role_name,
                issue="Role has administrative access",
                severity=ScanSeverity.CRITICAL,
                description=f"IAM role '{role_name}' has administrative privileges",
                recommendation="Apply principle of least privilege. Remove unnecessary administrative permissions.",
                terraform_patch=self._generate_role_policy_patch(role_name, "Remove admin access")
            ))
        
        # Check for wildcard permissions
        wildcard_actions = await self._check_wildcard_permissions(role)
        if wildcard_actions:
            self.add_finding(SecurityFinding(
                resource_type="aws_iam_role",
                resource_id=role_arn,
                resource_name=role_name,
                issue="Role has wildcard permissions",
                severity=ScanSeverity.HIGH,
                description=f"IAM role '{role_name}' has wildcard permissions: {', '.join(wildcard_actions)}",
                recommendation="Replace wildcard permissions with specific actions",
                terraform_patch=self._generate_role_policy_patch(role_name, "Replace wildcards with specific actions")
            ))
        
        # Check for unused roles
        if await self._is_role_unused(role):
            self.add_finding(SecurityFinding(
                resource_type="aws_iam_role",
                resource_id=role_arn,
                resource_name=role_name,
                issue="Unused IAM role",
                severity=ScanSeverity.MEDIUM,
                description=f"IAM role '{role_name}' appears to be unused",
                recommendation="Delete unused roles to reduce attack surface"
            ))
        
        # Check for overly permissive trust policies
        trust_issues = await self._check_trust_policy(role)
        for issue in trust_issues:
            self.add_finding(SecurityFinding(
                resource_type="aws_iam_role",
                resource_id=role_arn,
                resource_name=role_name,
                issue=issue['issue'],
                severity=issue['severity'],
                description=issue['description'],
                recommendation=issue['recommendation'],
                terraform_patch=self._generate_trust_policy_patch(role_name)
            ))
    
    async def _has_admin_access(self, role: Dict[str, Any]) -> bool:
        """Check if role has administrative access"""
        try:
            # Get attached policies
            attached_policies = self.iam_client.list_attached_role_policies(RoleName=role['RoleName'])
            
            # Check for AWS managed admin policies
            admin_policies = [
                'arn:aws:iam::aws:policy/AdministratorAccess',
                'arn:aws:iam::aws:policy/PowerUserAccess'
            ]
            
            for policy in attached_policies['AttachedPolicies']:
                if policy['PolicyArn'] in admin_policies:
                    return True
            
            # Check inline policies for admin access
            inline_policies = self.iam_client.list_role_policies(RoleName=role['RoleName'])
            for policy_name in inline_policies['PolicyNames']:
                policy_doc = self.iam_client.get_role_policy(
                    RoleName=role['RoleName'],
                    PolicyName=policy_name
                )
                
                if self._policy_has_admin_access(policy_doc['PolicyDocument']):
                    return True
            
            return False
            
        except ClientError:
            return False
    
    def _policy_has_admin_access(self, policy_doc: Dict[str, Any]) -> bool:
        """Check if policy document grants admin access"""
        for statement in policy_doc.get('Statement', []):
            if statement.get('Effect') == 'Allow':
                actions = statement.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                
                # Check for admin actions
                admin_actions = ['*', 'iam:*', 's3:*', 'ec2:*']
                if any(action in admin_actions for action in actions):
                    return True
        
        return False
    
    async def _check_wildcard_permissions(self, role: Dict[str, Any]) -> List[str]:
        """Check for wildcard permissions in role policies"""
        wildcard_actions = []
        
        try:
            # Check attached policies
            attached_policies = self.iam_client.list_attached_role_policies(RoleName=role['RoleName'])
            for policy in attached_policies['AttachedPolicies']:
                policy_doc = self.iam_client.get_policy(PolicyArn=policy['PolicyArn'])
                version = self.iam_client.get_policy_version(
                    PolicyArn=policy['PolicyArn'],
                    VersionId=policy_doc['Policy']['DefaultVersionId']
                )
                
                wildcards = self._find_wildcard_actions(version['PolicyVersion']['Document'])
                wildcard_actions.extend(wildcards)
            
            # Check inline policies
            inline_policies = self.iam_client.list_role_policies(RoleName=role['RoleName'])
            for policy_name in inline_policies['PolicyNames']:
                policy_doc = self.iam_client.get_role_policy(
                    RoleName=role['RoleName'],
                    PolicyName=policy_name
                )
                
                wildcards = self._find_wildcard_actions(policy_doc['PolicyDocument'])
                wildcard_actions.extend(wildcards)
                
        except ClientError:
            pass
        
        return list(set(wildcard_actions))  # Remove duplicates
    
    def _find_wildcard_actions(self, policy_doc: Dict[str, Any]) -> List[str]:
        """Find wildcard actions in policy document"""
        wildcards = []
        
        for statement in policy_doc.get('Statement', []):
            if statement.get('Effect') == 'Allow':
                actions = statement.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                
                for action in actions:
                    if '*' in action and action != '*':
                        wildcards.append(action)
        
        return wildcards
    
    async def _is_role_unused(self, role: Dict[str, Any]) -> bool:
        """Check if role is unused (simplified check)"""
        try:
            # Check last used date
            if 'RoleLastUsed' in role and role['RoleLastUsed'].get('LastUsedDate'):
                last_used = role['RoleLastUsed']['LastUsedDate']
                days_since_use = (datetime.now(last_used.tzinfo) - last_used).days
                return days_since_use > 90  # Consider unused if not used in 90 days
            
            return True  # No last used date means likely unused
            
        except Exception:
            return False
    
    async def _check_trust_policy(self, role: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check role trust policy for security issues"""
        issues = []
        trust_policy = role.get('AssumeRolePolicyDocument', {})
        
        for statement in trust_policy.get('Statement', []):
            if statement.get('Effect') == 'Allow':
                principal = statement.get('Principal', {})
                
                # Check for wildcard principals
                if '*' in str(principal):
                    issues.append({
                        'issue': 'Trust policy allows wildcard principal',
                        'severity': ScanSeverity.CRITICAL,
                        'description': f"Role trust policy allows wildcard principal access",
                        'recommendation': 'Restrict trust policy to specific principals'
                    })
                
                # Check for overly broad service access
                if 'Service' in principal:
                    services = principal['Service']
                    if isinstance(services, str):
                        services = [services]
                    
                    for service in services:
                        if service == '*':
                            issues.append({
                                'issue': 'Trust policy allows all AWS services',
                                'severity': ScanSeverity.HIGH,
                                'description': f"Role trust policy allows all AWS services to assume the role",
                                'recommendation': 'Restrict to specific AWS services'
                            })
        
        return issues
    
    async def _scan_users(self):
        """Scan IAM users for security issues"""
        try:
            paginator = self.iam_client.get_paginator('list_users')
            
            for page in paginator.paginate():
                for user in page['Users']:
                    await self._analyze_user(user)
                    
        except ClientError as e:
            self.add_finding(SecurityFinding(
                resource_type="aws_iam_users",
                resource_id="all_users",
                issue="Cannot list IAM users",
                severity=ScanSeverity.HIGH,
                description=f"Failed to list IAM users: {str(e)}",
                recommendation="Ensure IAM credentials have iam:ListUsers permission"
            ))
    
    async def _analyze_user(self, user: Dict[str, Any]):
        """Analyze individual IAM user for security issues"""
        username = user['UserName']
        user_arn = user['Arn']
        
        # Check for admin access
        if await self._user_has_admin_access(username):
            self.add_finding(SecurityFinding(
                resource_type="aws_iam_user",
                resource_id=user_arn,
                resource_name=username,
                issue="User has administrative access",
                severity=ScanSeverity.CRITICAL,
                description=f"IAM user '{username}' has administrative privileges",
                recommendation="Apply principle of least privilege. Remove unnecessary administrative permissions."
            ))
    
    async def _user_has_admin_access(self, username: str) -> bool:
        """Check if user has administrative access"""
        try:
            attached_policies = self.iam_client.list_attached_user_policies(UserName=username)
            
            admin_policies = [
                'arn:aws:iam::aws:policy/AdministratorAccess',
                'arn:aws:iam::aws:policy/PowerUserAccess'
            ]
            
            for policy in attached_policies['AttachedPolicies']:
                if policy['PolicyArn'] in admin_policies:
                    return True
            
            return False
            
        except ClientError:
            return False
    
    async def _scan_policies(self):
        """Scan customer managed policies for issues"""
        # Implementation for policy scanning
        pass
    
    async def _scan_groups(self):
        """Scan IAM groups for security issues"""
        # Implementation for group scanning
        pass
    
    async def _scan_access_keys(self):
        """Scan access keys for security issues"""
        # Implementation for access key scanning
        pass
    
    def _generate_role_policy_patch(self, role_name: str, description: str) -> str:
        """Generate Terraform patch for role policy"""
        return f'''
# Terraform patch for IAM role: {role_name}
# {description}

resource "aws_iam_role" "{role_name.replace('-', '_')}" {{
  name = "{role_name}"
  
  # TODO: Review and restrict permissions
  # Current policy may be overly permissive
}}
'''
    
    def _generate_trust_policy_patch(self, role_name: str) -> str:
        """Generate Terraform patch for trust policy"""
        return f'''
# Terraform patch for IAM role trust policy: {role_name}
# Restrict trust policy to specific principals

resource "aws_iam_role" "{role_name.replace('-', '_')}" {{
  name = "{role_name}"
  
  assume_role_policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [
      {{
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {{
          # TODO: Replace with specific principals
          # Avoid wildcards in Principal
        }}
      }}
    ]
  }})
}}
'''
    
    def get_scanner_name(self) -> str:
        return "AWS IAM Security Scanner"
