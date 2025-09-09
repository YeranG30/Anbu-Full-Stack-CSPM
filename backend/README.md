# Anbu CSPM Backend

**Cloud Security Posture Manager Backend** - Real cloud security scanning with AWS and GCP integration.

## 🚀 Features

### ✅ Implemented
- **AWS IAM Scanner**: Detects admin roles, wildcard permissions, unused roles
- **AWS S3 Scanner**: Finds public buckets, overly permissive policies, encryption issues
- **Scanner Manager**: Orchestrates multiple scanners with concurrent execution
- **FastAPI Integration**: RESTful API with background scanning
- **Terraform Remediation**: Generates Terraform code to fix issues
- **Configuration Management**: Environment-based cloud provider setup
- **Comprehensive Logging**: Detailed scan results and error tracking

### 🔄 In Progress
- GCP IAM Scanner
- GCP Storage Scanner
- Scanning Scheduler
- Advanced Error Handling

## 🛠️ Quick Start

### 1. Install Dependencies
```bash
cd backend
pip install -r requirements.txt
```

### 2. Configure Cloud Providers

#### AWS Setup
```bash
# Option 1: Environment variables
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_DEFAULT_REGION=us-east-1

# Option 2: AWS CLI (recommended)
aws configure

# Option 3: IAM Role (for EC2/ECS)
# Set AWS_ROLE_ARN environment variable
```

#### GCP Setup (Future)
```bash
# Set up service account
export GCP_PROJECT_ID=your_project_id
export GOOGLE_APPLICATION_CREDENTIALS=path/to/service-account-key.json
```

### 3. Run the Backend
```bash
# Development server
uvicorn main:app --reload --host 0.0.0.0 --port 8000

# Production server
uvicorn main:app --host 0.0.0.0 --port 8000
```

### 4. Test the API
```bash
# Test the backend
python test_cspm.py

# Or visit the interactive docs
open http://localhost:8000/docs
```

## 📡 API Endpoints

### Core Endpoints
- `GET /health` - Health check and cloud provider status
- `GET /findings` - Get all security findings from database
- `POST /scan` - Start a new security scan (background)
- `GET /scan/status` - Get current scan status and summary
- `GET /scan/findings` - Get findings from the last scan
- `GET /scan/export` - Export findings as JSON
- `GET /scanners` - List all registered scanners

### Example Usage

#### Start a Scan
```bash
curl -X POST "http://localhost:8000/scan" \
  -H "Content-Type: application/json" \
  -d '{"providers": ["aws"], "regions": ["us-east-1"]}'
```

#### Get Scan Results
```bash
curl "http://localhost:8000/scan/findings"
```

#### Check Health
```bash
curl "http://localhost:8000/health"
```

## 🔍 Security Scanners

### AWS IAM Scanner
Detects:
- **Admin Access**: Roles/users with administrative privileges
- **Wildcard Permissions**: Policies with `*` or `s3:*` actions
- **Unused Roles**: Roles not used in 90+ days
- **Trust Policy Issues**: Overly permissive assume role policies

### AWS S3 Scanner
Detects:
- **Public Access**: Buckets accessible to the public
- **Overly Permissive Policies**: Bucket policies with wildcard principals
- **Missing Encryption**: Buckets without server-side encryption
- **Missing Versioning**: Buckets without versioning enabled

## 🏗️ Architecture

```
backend/
├── core/
│   ├── config.py          # Configuration management
│   ├── base_scanner.py    # Abstract scanner interface
│   └── scanner_manager.py # Scanner orchestration
├── scanner/
│   ├── iam/
│   │   └── aws_iam_scanner.py
│   └── exposure/
│       └── aws_s3_scanner.py
├── api/
│   └── schemas.py         # Pydantic models
├── db/
│   ├── models.py          # SQLAlchemy models
│   └── database.py        # Database configuration
├── main.py               # FastAPI application
└── requirements.txt      # Dependencies
```

## 🔧 Configuration

### Environment Variables
```bash
# Database
DATABASE_URL=sqlite:///./anbu.db

# AWS
AWS_ACCESS_KEY_ID=your_key
AWS_SECRET_ACCESS_KEY=your_secret
AWS_DEFAULT_REGION=us-east-1

# GCP (future)
GCP_PROJECT_ID=your_project
GOOGLE_APPLICATION_CREDENTIALS=path/to/key.json

# Scanning
SCAN_INTERVAL_MINUTES=60
MAX_CONCURRENT_SCANS=5
ENABLE_AWS_SCANNING=true
ENABLE_GCP_SCANNING=false
```

## 📊 Sample Output

### Scan Results
```json
{
  "scan_id": "scan_1703123456",
  "total_findings": 15,
  "severity_breakdown": {
    "critical": 3,
    "high": 7,
    "medium": 4,
    "low": 1
  },
  "scanners_run": 4,
  "duration_seconds": 45.2
}
```

### Security Finding
```json
{
  "provider": "aws",
  "resource_type": "aws_iam_role",
  "resource_id": "arn:aws:iam::123456789012:role/AdminRole",
  "issue": "Role has administrative access",
  "severity": "critical",
  "description": "IAM role 'AdminRole' has administrative privileges",
  "recommendation": "Apply principle of least privilege. Remove unnecessary administrative permissions.",
  "terraform_patch": "resource \"aws_iam_role\" \"admin_role\" { ... }"
}
```

## 🚨 Security Considerations

- **Credentials**: Never commit AWS/GCP credentials to version control
- **IAM Permissions**: Use least privilege principle for scanner credentials
- **Network**: Run in secure network environment
- **Logging**: Monitor logs for sensitive information exposure

## 🔮 Roadmap

- [ ] GCP IAM and Storage scanners
- [ ] Azure support
- [ ] Real-time scanning with WebSockets
- [ ] Advanced remediation workflows
- [ ] Compliance reporting (SOC2, PCI-DSS)
- [ ] Multi-tenant support
- [ ] Custom policy rules

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Implement your changes
4. Add tests
5. Submit a pull request

## 📄 License

MIT License - see LICENSE file for details.
