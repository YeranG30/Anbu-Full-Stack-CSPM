from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from .models import Base

# conection to sqlite db in the backend folder 
DATABASE_URL = "sqlite:///./anbu.db"

# will create the db enginer 
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}  # i believe only req for SQLite
)

# 3. creating a session factory 
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# 4. creating all tables at startup
def init_db():
    Base.metadata.create_all(bind=engine)
