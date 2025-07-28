from pydantic import BaseModel
from datetime import datetime
from typing import Optional

# using pydantic to allow clean coversion from sql to json for react front end

class FindingOut(BaseModel):
    id: int
    provider: str
    resource_type: str
    resource_id: str
    issue: str
    severity: str
    recommendation: Optional[str]
    terraform_patch: Optional[str]
    timestamp: datetime

    class Config:
        orm_mode = True  # allows SQLAlchemy  to Pydantic conversion
