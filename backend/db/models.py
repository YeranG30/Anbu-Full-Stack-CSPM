from sqlalchemy import Column, Integer, String, Text, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func
from datetime import datetime

Base = declarative_base()

#data values for findings 
class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    provider = Column(String, nullable=False)
    resource_type = Column(String, nullable=False)
    resource_id = Column(String, nullable=False)
    issue = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    recommendation = Column(Text)
    terraform_patch = Column(Text)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
