#  Anbu – Full Stack Cloud Security Posture Manager (CSPM)

**Anbu** is a full-stack Cloud Security Posture Manager (CSPM) designed to detect, visualize, and remediate misconfigurations in cloud environments like AWS and GCP. It supports identity misconfigurations, overly permissive access, and public exposure such as `0.0.0.0/0`.

>  **Currently focused on IAM misconfiguration detection and a frontend dashboard for real-time cloud posture visualization.**

---

##  Project Goals

* Build a CSPM that scans for cloud misconfigurations (IAM, exposure, secrets)
* Auto-generate Terraform-based remediations
* Visualize findings in a modern, intuitive dashboard
* Support multi-cloud: AWS + GCP

---

##  Current Sprint – IAM + Exposure + Dashboard

> Jira-style Epic: **CSPM: Identity Misconfig + Public Exposure Dashboard**

**Backlog Objectives:**
- [x] IAM misconfig detection logic (admin roles, wildcard permissions, service accounts)
- [x] Detect 0.0.0.0/0 access in firewall/storage/IAM policies
- [ ] Generate Terraform diff for misconfigs
- [ ] Display scan results in dashboard
- [ ] Filter findings by cloud provider, service, severity
- [ ] Export findings to JSON

---

##  Tech Stack

###  Frontend (Dashboard)
| Tech      | Purpose                                |
|-----------|----------------------------------------|
| React     | Component-based UI framework           |
| Tailwind  | Utility-first CSS for styling          |
| Recharts  | Data visualization (bar, pie, radar)   |
| Axios     | API calls to backend                   |
| Zustand   | State management                       |

###  Backend
| Tech        | Purpose                                      |
|-------------|----------------------------------------------|
| Python      | Core logic for scanning                      |
| FastAPI     | REST API for frontend communication          |
| SQLAlchemy  | ORM for PostgreSQL                           |
| Docker      | Containerized CSPM engine                    |

###  Cloud + IaC
| Tech        | Purpose                                        |
|-------------|------------------------------------------------|
| Terraform   | IaC parsing and remediation generation         |
| Sentinel    | Policy-as-code enforcement                     |
| AWS / GCP   | IAM, Firewall, Storage scanning                |

---

##  Dashboard Preview (Planned)

*Overview Page*
- Cloud Posture Score
-  Misconfig Findings by Cloud (AWS/GCP)
- IAM Role Risk Summary
-  0.0.0.0/0 Exposure Visuals

*Details Page*
- Filter by severity: High / Medium / Low
- View exact JSON policy causing the misconfig
- Terraform remediation preview
- "Remediate Now" button (future)

---

## CLI Preview

```bash
# Scan IAM configs
anbu scan --module iam --provider gcp

# Check for public exposure (e.g., 0.0.0.0/0)
anbu scan --module exposure --provider aws

# View findings
anbu findings list --filter severity=high

# Export
anbu export --format json
