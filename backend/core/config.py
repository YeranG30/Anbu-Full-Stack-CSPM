"""
Cloud Security Posture Manager - Configuration Management
Handles cloud provider credentials and environment settings
"""

import os
from typing import Optional, Dict, Any
from pydantic_settings import BaseSettings
from pydantic import Field
from enum import Enum

class CloudProvider(str, Enum):
    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"

class ScanSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class Settings(BaseSettings):
    """Application settings with environment variable support"""
    
    # Database
    database_url: str = Field(default="sqlite:///./anbu.db", env="DATABASE_URL")
    
    # AWS Configuration
    aws_access_key_id: Optional[str] = Field(default=None, env="AWS_ACCESS_KEY_ID")
    aws_secret_access_key: Optional[str] = Field(default=None, env="AWS_SECRET_ACCESS_KEY")
    aws_session_token: Optional[str] = Field(default=None, env="AWS_SESSION_TOKEN")
    aws_region: str = Field(default="us-east-1", env="AWS_DEFAULT_REGION")
    aws_role_arn: Optional[str] = Field(default=None, env="AWS_ROLE_ARN")
    
    # GCP Configuration
    gcp_project_id: Optional[str] = Field(default=None, env="GCP_PROJECT_ID")
    gcp_service_account_key: Optional[str] = Field(default=None, env="GCP_SERVICE_ACCOUNT_KEY")
    gcp_credentials_file: Optional[str] = Field(default=None, env="GOOGLE_APPLICATION_CREDENTIALS")
    
    # Scanning Configuration
    scan_interval_minutes: int = Field(default=60, env="SCAN_INTERVAL_MINUTES")
    max_concurrent_scans: int = Field(default=5, env="MAX_CONCURRENT_SCANS")
    enable_aws_scanning: bool = Field(default=True, env="ENABLE_AWS_SCANNING")
    enable_gcp_scanning: bool = Field(default=True, env="ENABLE_GCP_SCANNING")
    
    # Logging
    log_level: str = Field(default="INFO", env="LOG_LEVEL")
    log_file: Optional[str] = Field(default=None, env="LOG_FILE")
    
    class Config:
        env_file = ".env"
        case_sensitive = False

# Global settings instance
settings = Settings()

def get_aws_config() -> Dict[str, Any]:
    """Get AWS configuration for boto3 clients"""
    config = {
        "region_name": settings.aws_region
    }
    
    if settings.aws_access_key_id:
        config.update({
            "aws_access_key_id": settings.aws_access_key_id,
            "aws_secret_access_key": settings.aws_secret_access_key
        })
        
        if settings.aws_session_token:
            config["aws_session_token"] = settings.aws_session_token
    
    if settings.aws_role_arn:
        config["role_arn"] = settings.aws_role_arn
    
    return config

def get_gcp_config() -> Dict[str, Any]:
    """Get GCP configuration for client libraries"""
    config = {}
    
    if settings.gcp_project_id:
        config["project_id"] = settings.gcp_project_id
    
    if settings.gcp_credentials_file:
        config["credentials_file"] = settings.gcp_credentials_file
    elif settings.gcp_service_account_key:
        config["service_account_key"] = settings.gcp_service_account_key
    
    return config

def validate_cloud_credentials() -> Dict[CloudProvider, bool]:
    """Validate cloud provider credentials are properly configured"""
    validation_results = {}
    
    # AWS Validation
    if settings.enable_aws_scanning:
        aws_valid = bool(
            settings.aws_access_key_id and settings.aws_secret_access_key
        ) or bool(settings.aws_role_arn)
        validation_results[CloudProvider.AWS] = aws_valid
    else:
        validation_results[CloudProvider.AWS] = False
    
    # GCP Validation
    if settings.enable_gcp_scanning:
        gcp_valid = bool(
            settings.gcp_project_id and (
                settings.gcp_credentials_file or 
                settings.gcp_service_account_key
            )
        )
        validation_results[CloudProvider.GCP] = gcp_valid
    else:
        validation_results[CloudProvider.GCP] = False
    
    return validation_results
