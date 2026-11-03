# DATAGuard

## AI-Powered Database Problem Detection & Resolution System

A local-first academic project for inspecting databases, explaining diagnostic findings, routing safe repair proposals through administrator approval, and verifying approved repairs.

## What works

- Registration and login with PBKDF2 password hashing and signed, expiring bearer tokens. The first registered account is the administrator; later accounts are viewers.
- Sample SQLite database with reproducible duplicate, null, and orphan-record findings.
- Custom SQLite, PostgreSQL, and MySQL connections through SQLAlchemy. Connection strings are held in process memory only and are not written to the application database.
- Schema explorer for tables, columns, foreign keys, and indexes.
- Read-only diagnostic queries for table/column metadata, null values, duplicate rows, and SQLite foreign-key violations. Missing-index candidates are reported from unindexed foreign keys.
- Rule-based plain-language explanations, impact, risk, and repair suggestions. No LLM is required or permitted to issue executable SQL.
- Administrator approval/rejection, a narrowly allowlisted `CREATE INDEX` repair executor, execution audit history, post-repair verification, and JSON health reports.
- Responsive dark dashboard served by FastAPI.

## Limitations

This is a local single-process demonstration, not a hardened multi-tenant deployment. Connection definitions (except their credentials) and accounts persist in `data/app.db`; active target connection strings are lost at restart and must be reconnected. Use a dedicated least-privilege, read-only account for analysis. MySQL/PostgreSQL driver and server availability depends on the environment. MongoDB, query-performance telemetry, unused-index detection, and automated duplicate/null cleanup are not implemented. Those findings are advisory and cannot be auto-repaired.

The only automated repair in this version is creation of a missing foreign-key index. The executor reconstructs the SQL from the approved finding rather than trusting submitted SQL. It never executes arbitrary SQL or destructive statements.

## Run locally

Requires Python 3.10+.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
$env:DBDIAG_SECRET = python -c "import secrets; print(secrets.token_urlsafe(48))"
python -m uvicorn app.main:app --reload
```

Open <http://127.0.0.1:8000>. Register the first account to create the administrator. Select **Add sample database**, then run an analysis. The demo sample is intentionally seeded with duplicate customer emails, missing email values, an orphan order, and a foreign-key column without an index. Approve the generated index proposal as the administrator to exercise repair and verification.

For a custom SQLite database, enter its path. For PostgreSQL/MySQL, provide a SQLAlchemy URL such as `postgresql+psycopg://user:password@host:5432/dbname` or `mysql+pymysql://user:password@host:3306/dbname`. Credentials submitted in the URL stay in process memory and are not logged or persisted. Do not expose this development server to an untrusted network.

## Deploy to Railway with Docker

1. Connect the GitHub repository to Railway and create a Railway project using that repository. Railway will detect the root `Dockerfile` and build the app.
2. Add a Railway **Volume** to the service, mounted at `/data`.
3. Set these service variables in Railway:
   - `DBDIAG_DATA_DIR=/data`
   - `DBDIAG_SECRET` to a long, random, persistent secret. Generate one locally with `python -c "import secrets; print(secrets.token_urlsafe(48))"` and enter it as a Railway variable; never commit it or put it in a Docker image.
   - `DBDIAG_ADMIN_SETUP_TOKEN` to a separate, long, random one-time bootstrap token. The first registration that supplies it becomes the administrator. Registrations without it are viewers. Generate it locally and share it only with the intended administrator.
4. Deploy. The container listens on Railway's injected `PORT`; do not hard-code a port in Railway. Open the public domain Railway assigns and enter the setup token when creating the administrator account.

The app and its seeded sample SQLite database both live under `DBDIAG_DATA_DIR`. Without the mounted volume, SQLite data is ephemeral and can be lost when Railway replaces the container. `seed_sample()` reinitializes the sample database at each app start, so treat it as demo data, not persistent user data. Keep the same `DBDIAG_SECRET` across deploys so existing login tokens remain verifiable; changing it invalidates them.

This app is designed for one running process and one service instance: SQLite is used for app state, while active target database connections are held in memory and disappear at restart. Do not scale it horizontally or run multiple worker processes. This is a demonstration, not a hardened public multi-tenant service; use strong account passwords, a stable secret, the administrator setup token, and least-privilege target database credentials. Restrict access to a trusted audience before connecting sensitive databases.

## Tests

```powershell
python -m unittest discover -s tests -v
```

The tests cover sample findings, index-repair allowlisting, and database connection metadata handling.
