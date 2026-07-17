from sqlmodel import SQLModel, Field
from datetime import datetime
from typing import Optional


class Scan(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)

    target: str
    status: str  # "queued" | "scanning_ports" | "scanning_web" | "complete" | "failed"

    # Celery task ID so the frontend can poll for progress
    task_id: Optional[str] = Field(default=None, index=True)

    # Phase tracking
    phase: Optional[str] = Field(default="queued")  # "nmap" | "nuclei" | "done"

    created_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = Field(default=None)


class Port(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)

    scan_id: int

    port: int
    service: str
    product: Optional[str] = None
    version: Optional[str] = None

    # True if this is a known web port (80, 443, 8000, 8080, etc.)
    is_web: Optional[bool] = Field(default=False)


class Vulnerability(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)

    port_id: int

    cve_id: str
    severity: str
    description: str


class NucleiFinding(SQLModel, table=True):
    """Structured findings from the Nuclei web scanner (Phase 2)."""
    id: Optional[int] = Field(default=None, primary_key=True)

    scan_id: int

    template_id: Optional[str] = None
    template_name: Optional[str] = None
    severity: Optional[str] = None          # info | low | medium | high | critical
    host: Optional[str] = None
    matched_at: Optional[str] = None        # URL where the finding was triggered
    description: Optional[str] = None
    tags: Optional[str] = None              # comma-separated list

    discovered_at: datetime = Field(default_factory=datetime.utcnow)
