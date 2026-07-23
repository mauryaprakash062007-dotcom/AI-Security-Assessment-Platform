import os
from sqlmodel import SQLModel, create_engine,Session
from models import Scan, Port, Vulnerability, NucleiFinding, AttackPath, AttackPathStep, ZeroDayAlert

# Reads from env so this works unchanged on localhost, a VM, or in Docker
# (docker-compose sets DATABASE_URL=postgresql://postgres:postgres@db/security_platform).
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://postgres:mypassword123@localhost/security_platform",
)

engine = create_engine(
    DATABASE_URL,
    echo=True
)

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

def get_session():
    return Session(engine)
