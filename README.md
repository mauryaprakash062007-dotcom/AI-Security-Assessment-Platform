# AI Security Assessment Platform

## Features
- FastAPI backend
- Nmap port/service scanning + Nuclei web vulnerability scanning (any target you own/are authorized to scan)
- CVE lookups (local DB + live NVD search)
- ML-based risk scoring (Random Forest, `ml_risk_engine.py`)
- PDF report generation
- PostgreSQL storage, Celery + Redis for async scan jobs
- React (Vite) frontend

> ⚠️ **Only scan hosts you own or are explicitly authorized to test.**
> Good practice targets: `scanme.nmap.org` (nmap's official test host),
> a VM you control, or a deliberately vulnerable app like OWASP Juice Shop / DVWA / Metasploitable.

## Run with Docker (recommended — works the same on any OS/VM)

Requires Docker + Docker Compose.

```bash
docker compose up --build
```

- Frontend → http://localhost:5173
- Backend API → http://localhost:8000

That's it — Postgres, Redis, the API, the Celery worker, nmap, and nuclei are all
provisioned automatically inside the containers. Nothing points at anyone's personal
machine anymore (see "Config" below for what used to be hardcoded).

If your frontend will be opened from a browser on a **different** machine than the
one running Docker (e.g. you're serving this from a VM and browsing from your host),
edit `VITE_API_URL` in `docker-compose.yml` under the `frontend` service to that VM's
reachable IP, e.g. `http://192.168.1.50:8000`, then rebuild:
```bash
docker compose up --build frontend
```

## Run locally without Docker

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# you also need nmap and nuclei installed locally and on PATH:
sudo apt install nmap
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates

# start Postgres + Redis yourself, then:
cp .env.example .env   # edit if your DB/Redis aren't on localhost
uvicorn main:app --reload
celery -A celery_app worker --loglevel=info   # in a second terminal

cd frontend
npm install
npm run dev
```

## Config

All previously-hardcoded values now read from environment variables (with your
local defaults kept as fallbacks), so the same code runs unmodified on your laptop,
a VM, or in Docker:

| Variable | Used by | Default |
|---|---|---|
| `DATABASE_URL` | `database.py` | `postgresql://postgres:mypassword123@localhost/security_platform` |
| `REDIS_URL` | `celery_app.py` | `redis://localhost:6379/0` |
| `NUCLEI_BIN` | `tasks.py` | `nuclei` (assumes it's on PATH) |
| `NUCLEI_TEMPLATES_DIR` | `tasks.py` | `~/nuclei-templates` |
| `VITE_API_URL` (frontend build arg) | `frontend/src/pages/*.jsx` | `http://127.0.0.1:8000` |
