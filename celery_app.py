"""
celery_app.py
─────────────
Single source of truth for the Celery application.
Import `celery_app` in both the worker (tasks.py) and the
FastAPI routes so they share the same broker/backend config.
"""

import os
from celery import Celery

# Redis is used as both the broker (job queue) and the result backend.
# Reads from env so this works unchanged on localhost, a VM, or in Docker
# (docker-compose sets REDIS_URL=redis://redis:6379/0).
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

celery_app = Celery(
    "scanner",
    broker=REDIS_URL,
    backend=REDIS_URL,
    include=["tasks"],          # module(s) that contain @celery_app.task
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    # Keep results for 24 h so the frontend can always poll them
    result_expires=86_400,
    # Prevent a hung Nmap/Nuclei process from blocking the worker forever
    task_time_limit=1500,       # hard kill after 25 min
    task_soft_time_limit=1200,  # SIGTERM after 20 min (lets us clean up)
    
    # Scheduled Tasks (Celery Beat)
    beat_schedule={
        "poll_zero_days_every_12_hours": {
            "task": "tasks.poll_threat_intelligence",
            "schedule": 43200.0, # 12 hours in seconds
        }
    }
)
