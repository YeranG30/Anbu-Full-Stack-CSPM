from fastapi import FastAPI, Depends
from sqlalchemy.orm import Session
from db.database import SessionLocal, init_db
from db import models
from db.models import Finding
from api.schemas import FindingOut
from typing import List


app = FastAPI()
init_db()

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
    return {"status": "ok"}

@app.get("/findings", response_model=List[FindingOut])
def read_findings(db: Session = Depends(get_db)):
    findings = db.query(models.Finding).all()
    return findings