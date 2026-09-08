# FastAPI Backend Service

A modular, high-performance FastAPI service built with **Python 3.12** and managed using **[uv](https://github.com/astral-sh/uv)**.

---

## 1. Prerequisites

- **Python 3.12** (managed automatically via `uv`)
- **uv**: Fast Python package installer and resolver (`>=0.12.0`)

---

## 2. Project Layout

```text
backend/
├── .venv/                      # Virtual environment created by uv
├── src/
│   └── backend/
│       ├── __init__.py         # Package entrypoint and exports
│       ├── main.py             # FastAPI app initialization, middleware & lifecycle
│       ├── config.py           # Pydantic Settings & environment config
│       ├── api/
│       │   ├── router.py       # Main API router aggregator
│       │   └── v1/
│       │       └── endpoints/
│       │           └── health.py # Health check endpoint (/api/v1/health)
│       └── schemas/
│           └── health.py       # Pydantic response models
├── tests/
│   ├── __init__.py
│   └── test_health.py          # Pytest suite with HTTPX async client
├── .env.example                # Sample environment variables
├── pyproject.toml              # Dependencies & build configuration
└── README.md
```

---

## 3. Development Commands

### Activate Virtual Environment
```powershell
# Windows PowerShell
.venv\Scripts\Activate.ps1
```

### Run the Development Server
Using `uv`:
```bash
uv run uvicorn backend.main:app --reload --port 8000
```
Or directly:
```bash
uv run backend
```

Once running, access:
- **Interactive OpenAPI Docs (Swagger UI)**: [http://127.0.0.1:8000/api/v1/docs](http://127.0.0.1:8000/api/v1/docs)
- **ReDoc Documentation**: [http://127.0.0.1:8000/api/v1/redoc](http://127.0.0.1:8000/api/v1/redoc)
- **Health Check Endpoint**: [http://127.0.0.1:8000/api/v1/health](http://127.0.0.1:8000/api/v1/health)

---

## 4. Run Tests

Run the test suite with `pytest`:
```bash
uv run pytest
```

---

## 5. Adding Dependencies

```bash
# Add production dependency
uv add <package_name>

# Add development dependency
uv add --dev <package_name>
```
