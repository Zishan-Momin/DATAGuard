import json
import hmac
import os
import re
import sqlite3
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import URL, create_engine, inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError

from app import storage as storage_module
from app.analyzer import analyze_database, build_index_sql
from app.security import create_token, hash_password, verify_password, verify_token
from app.storage import ROOT, connect_app, init_storage, seed_sample


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_storage()
    seed_sample()
    try:
        yield
    finally:
        shutdown_engines()


app = FastAPI(title="Database Health", version="1.0.0", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")
active_engines: dict[str, Engine] = {}


class Credentials(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=10, max_length=128)


class RegistrationCredentials(Credentials):
    admin_setup_token: str | None = Field(default=None, max_length=256)


class ConnectionInput(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    backend: str
    connection_url: str = Field(min_length=1, max_length=2000)


def current_user(authorization: Annotated[str | None, Header()] = None) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Sign in to continue.")
    payload = verify_token(authorization[7:])
    if not payload:
        raise HTTPException(status_code=401, detail="Your session expired. Please sign in again.")
    with connect_app() as db:
        user = db.execute("SELECT id, email, role FROM users WHERE id = ?", (payload["sub"],)).fetchone()
    if not user:
        raise HTTPException(status_code=401, detail="Account not found.")
    return dict(user)


def require_admin(user: dict = Depends(current_user)) -> dict:
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Administrator approval is required.")
    return user


def make_engine(backend: str, url: str) -> Engine:
    if backend == "SQLite":
        if url == "sample":
            db_url = URL.create("sqlite", database=str(storage_module.SAMPLE_DB))
        else:
            if "://" in url:
                raise ValueError("For SQLite, enter a local database file path.")
            db_url = URL.create("sqlite", database=url)
    elif backend in ("PostgreSQL", "MySQL"):
        expected = "postgresql+" if backend == "PostgreSQL" else "mysql+"
        if not url.startswith(expected):
            raise ValueError(f"Enter a SQLAlchemy {backend} URL beginning with {expected}...")
        if re.search(r"[\r\n]", url):
            raise ValueError("The connection URL contains invalid characters.")
        db_url = url
    else:
        raise ValueError("Supported backends are SQLite, PostgreSQL, and MySQL.")
    return create_engine(db_url, pool_pre_ping=True, connect_args={"timeout": 5} if backend == "SQLite" else {})


def owned_connection(connection_id: str, user: dict) -> Engine:
    with connect_app() as db:
        record = db.execute(
            "SELECT id FROM connections WHERE id = ? AND owner_id = ?",
            (connection_id, user["id"]),
        ).fetchone()
    if not record:
        raise HTTPException(status_code=404, detail="Database connection not found.")
    engine = active_engines.get(connection_id)
    if engine is None:
        raise HTTPException(status_code=409, detail="Reconnect this database after the server restarted.")
    return engine


def audit(db, repair_id: str, actor_id: int, action: str, detail: str) -> None:
    db.execute(
        "INSERT INTO audit_log(repair_id, actor_id, action, detail) VALUES (?, ?, ?, ?)",
        (repair_id, actor_id, action, detail),
    )


@app.get("/")
def home():
    return FileResponse(ROOT / "static" / "index.html")


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.post("/api/auth/register")
def register(body: RegistrationCredentials):
    email = body.email.strip().lower()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise HTTPException(status_code=422, detail="Enter a valid email address.")
    try:
        with connect_app() as db:
            db.execute("BEGIN IMMEDIATE")
            setup_token = os.environ.get("DBDIAG_ADMIN_SETUP_TOKEN")
            if setup_token:
                admin_count = db.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'").fetchone()[0]
                supplied_token = body.admin_setup_token or ""
                role = (
                    "admin"
                    if admin_count == 0 and hmac.compare_digest(supplied_token, setup_token)
                    else "viewer"
                )
            else:
                user_count = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
                role = "admin" if user_count == 0 else "viewer"
            cursor = db.execute(
                "INSERT INTO users(email, password_hash, role) VALUES (?, ?, ?)",
                (email, hash_password(body.password), role),
            )
            user = {"id": cursor.lastrowid, "email": email, "role": role}
    except sqlite3.IntegrityError as exc:
        if "users.email" in str(exc):
            raise HTTPException(status_code=409, detail="An account with this email already exists.") from exc
        raise
    return {"token": create_token(user["id"], role), "user": user}


@app.post("/api/auth/login")
def login(body: Credentials):
    with connect_app() as db:
        row = db.execute("SELECT * FROM users WHERE email = ?", (body.email.strip().lower(),)).fetchone()
    if not row or not verify_password(body.password, row["password_hash"]):
        raise HTTPException(status_code=401, detail="Email or password is incorrect.")
    user = {"id": row["id"], "email": row["email"], "role": row["role"]}
    return {"token": create_token(user["id"], user["role"]), "user": user}


@app.get("/api/auth/me")
def me(user: dict = Depends(current_user)):
    return {"user": user}


@app.post("/api/connections/test")
def test_connection(body: ConnectionInput, user: dict = Depends(current_user)):
    try:
        engine = make_engine(body.backend, body.connection_url)
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        engine.dispose()
        return {"ok": True, "message": f"Connected to {body.backend} successfully."}
    except (SQLAlchemyError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=f"Connection failed: {exc}") from exc


@app.post("/api/connections")
def add_connection(body: ConnectionInput, user: dict = Depends(current_user)):
    try:
        engine = make_engine(body.backend, body.connection_url)
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except (SQLAlchemyError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=f"Connection failed: {exc}") from exc
    connection_id = str(uuid.uuid4())
    with connect_app() as db:
        db.execute(
            "INSERT INTO connections(id, owner_id, name, backend) VALUES (?, ?, ?, ?)",
            (connection_id, user["id"], body.name.strip(), body.backend),
        )
    active_engines[connection_id] = engine
    return {"id": connection_id, "name": body.name.strip(), "backend": body.backend}


@app.post("/api/connections/sample")
def add_sample(user: dict = Depends(current_user)):
    body = ConnectionInput(name="Diagnostic sample database", backend="SQLite", connection_url="sample")
    connection_id = str(uuid.uuid4())
    engine = make_engine(body.backend, body.connection_url)
    with engine.connect() as connection:
        connection.execute(text("SELECT 1"))
    with connect_app() as db:
        db.execute(
            "INSERT INTO connections(id, owner_id, name, backend) VALUES (?, ?, ?, ?)",
            (connection_id, user["id"], body.name, body.backend),
        )
    active_engines[connection_id] = engine
    return {"id": connection_id, "name": body.name, "backend": body.backend}


@app.get("/api/connections")
def list_connections(user: dict = Depends(current_user)):
    with connect_app() as db:
        rows = db.execute(
            "SELECT id, name, backend, created_at FROM connections WHERE owner_id = ? ORDER BY created_at DESC",
            (user["id"],),
        ).fetchall()
    return [dict(row, connected=row["id"] in active_engines) for row in rows]


@app.get("/api/connections/{connection_id}/schema")
def explore_schema(connection_id: str, user: dict = Depends(current_user)):
    engine = owned_connection(connection_id, user)
    inspector = inspect(engine)
    try:
        tables = []
        for table_name in inspector.get_table_names():
            tables.append(
                {
                    "name": table_name,
                    "columns": [
                        {
                            "name": column["name"],
                            "type": str(column["type"]),
                            "nullable": bool(column.get("nullable", True)) and not bool(column.get("primary_key")),
                            "primary_key": bool(column.get("primary_key")),
                        }
                        for column in inspector.get_columns(table_name)
                    ],
                    "foreign_keys": inspector.get_foreign_keys(table_name),
                    "indexes": inspector.get_indexes(table_name),
                }
            )
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=400, detail=f"Schema inspection failed: {exc}") from exc
    return {"database": engine.dialect.name, "tables": tables}


@app.post("/api/analysis/{connection_id}")
def run_analysis(connection_id: str, user: dict = Depends(current_user)):
    engine = owned_connection(connection_id, user)
    try:
        result = analyze_database(engine)
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=400, detail=f"Analysis failed: {exc}") from exc
    analysis_id = str(uuid.uuid4())
    with connect_app() as db:
        db.execute(
            "INSERT INTO analyses(id, connection_id, owner_id, tables_analyzed, health_score, summary_json) VALUES (?, ?, ?, ?, ?, ?)",
            (analysis_id, connection_id, user["id"], len(result["tables"]), result["health_score"], json.dumps(result["summary"])),
        )
        for finding in result["findings"]:
            finding_id = str(uuid.uuid4())
            finding["id"] = finding_id
            db.execute(
                """INSERT INTO findings(id, analysis_id, connection_id, owner_id, name, category, severity, status,
                   table_name, column_name, description, root_cause, recommendation, impact, risk, repair_kind)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    finding_id, analysis_id, connection_id, user["id"], finding["name"], finding["category"],
                    finding["severity"], finding["status"], finding["table_name"], finding["column_name"],
                    finding["description"], finding["root_cause"], finding["recommendation"], finding["impact"],
                    finding["risk"], finding["repair_kind"],
                ),
            )
    return {"analysis_id": analysis_id, **result}


@app.get("/api/analyses")
def list_analyses(user: dict = Depends(current_user)):
    with connect_app() as db:
        rows = db.execute(
            """SELECT a.*, c.name AS connection_name FROM analyses a JOIN connections c ON c.id = a.connection_id
               WHERE a.owner_id = ? ORDER BY a.created_at DESC LIMIT 50""",
            (user["id"],),
        ).fetchall()
    return [dict(row, summary=json.loads(row["summary_json"])) for row in rows]


@app.get("/api/findings")
def list_findings(user: dict = Depends(current_user)):
    with connect_app() as db:
        rows = db.execute(
            "SELECT * FROM findings WHERE owner_id = ? ORDER BY created_at DESC LIMIT 200",
            (user["id"],),
        ).fetchall()
    return [dict(row) for row in rows]


@app.post("/api/findings/{finding_id}/propose")
def propose_repair(finding_id: str, user: dict = Depends(current_user)):
    with connect_app() as db:
        finding = db.execute(
            "SELECT * FROM findings WHERE id = ? AND owner_id = ?",
            (finding_id, user["id"]),
        ).fetchone()
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found.")
        if finding["repair_kind"] != "create_index" or finding["status"] != "potential":
            raise HTTPException(status_code=400, detail="This finding has no supported automated repair.")
        engine = owned_connection(finding["connection_id"], user)
        sql_preview = build_index_sql(engine, finding["table_name"], finding["column_name"], f"ix_{finding['table_name']}_{finding['column_name']}")
        repair_id = str(uuid.uuid4())
        db.execute(
            "INSERT INTO repairs(id, finding_id, connection_id, owner_id, requested_by, status, sql_preview) VALUES (?, ?, ?, ?, ?, 'pending', ?)",
            (repair_id, finding_id, finding["connection_id"], user["id"], user["id"], sql_preview),
        )
        db.execute("UPDATE findings SET repair_status = 'pending' WHERE id = ?", (finding_id,))
        audit(db, repair_id, user["id"], "proposed", "Repair submitted for administrator approval.")
    return {"id": repair_id, "status": "pending", "sql_preview": sql_preview}


@app.get("/api/repairs")
def list_repairs(user: dict = Depends(current_user)):
    where_clause = "" if user["role"] == "admin" else "WHERE r.owner_id = ?"
    with connect_app() as db:
        rows = db.execute(
            """SELECT r.*, f.name AS finding_name, f.description, f.recommendation, f.risk,
                      c.name AS connection_name
               FROM repairs r JOIN findings f ON f.id = r.finding_id
               JOIN connections c ON c.id = r.connection_id """
            + where_clause
            + " ORDER BY r.created_at DESC",
            () if user["role"] == "admin" else (user["id"],),
        ).fetchall()
    return [dict(row) for row in rows]


@app.post("/api/repairs/{repair_id}/decision")
def decide_repair(repair_id: str, body: dict, admin: dict = Depends(require_admin)):
    decision = body.get("decision")
    if decision not in ("approved", "rejected"):
        raise HTTPException(status_code=422, detail="Decision must be approved or rejected.")
    with connect_app() as db:
        repair = db.execute("SELECT * FROM repairs WHERE id = ?", (repair_id,)).fetchone()
        if not repair:
            raise HTTPException(status_code=404, detail="Repair proposal not found.")
        if repair["status"] != "pending":
            raise HTTPException(status_code=409, detail="This proposal has already been reviewed.")
        db.execute(
            "UPDATE repairs SET status = ?, approved_by = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (decision, admin["id"], repair_id),
        )
        db.execute("UPDATE findings SET repair_status = ? WHERE id = ?", (decision, repair["finding_id"]))
        audit(db, repair_id, admin["id"], decision, "Administrator reviewed the proposal.")
    return {"id": repair_id, "status": decision}


@app.post("/api/repairs/{repair_id}/execute")
def execute_repair(repair_id: str, admin: dict = Depends(require_admin)):
    with connect_app() as db:
        repair = db.execute(
            """SELECT r.*, f.table_name, f.column_name FROM repairs r
               JOIN findings f ON f.id = r.finding_id WHERE r.id = ?""",
            (repair_id,),
        ).fetchone()
        if not repair:
            raise HTTPException(status_code=404, detail="Repair proposal not found.")
        if repair["status"] != "approved":
            raise HTTPException(status_code=409, detail="Only an approved repair can be executed.")
        engine = owned_connection(repair["connection_id"], {"id": repair["owner_id"]})
        try:
            statement = build_index_sql(
                engine, repair["table_name"], repair["column_name"],
                f"ix_{repair['table_name']}_{repair['column_name']}",
            )
            if statement != repair["sql_preview"] or not statement.startswith("CREATE INDEX "):
                raise ValueError("The stored operation does not match the approved safe repair.")
            with engine.begin() as connection:
                connection.exec_driver_sql(statement)
            indexes = {index["name"] for index in inspect(engine).get_indexes(repair["table_name"])}
            verified = f"ix_{repair['table_name']}_{repair['column_name']}" in indexes
            if not verified:
                raise RuntimeError("The index was not visible during post-repair verification.")
            db.execute(
                """UPDATE repairs SET status = 'executed', execution_result = ?, verified = 1,
                   updated_at = CURRENT_TIMESTAMP WHERE id = ?""",
                ("Index created and verified.", repair_id),
            )
            db.execute("UPDATE findings SET repair_status = 'resolved' WHERE id = ?", (repair["finding_id"],))
            audit(db, repair_id, admin["id"], "executed", statement)
        except (SQLAlchemyError, ValueError, RuntimeError) as exc:
            db.execute(
                """UPDATE repairs SET status = 'failed', execution_result = ?, error_detail = ?,
                   updated_at = CURRENT_TIMESTAMP WHERE id = ?""",
                ("Execution failed; no success was recorded.", str(exc), repair_id),
            )
            audit(db, repair_id, admin["id"], "failed", str(exc))
            raise HTTPException(status_code=400, detail=f"Repair failed safely: {exc}") from exc
    return {"id": repair_id, "status": "executed", "verified": True}


@app.get("/api/audit")
def list_audit(user: dict = Depends(current_user)):
    where_clause = "" if user["role"] == "admin" else "WHERE r.owner_id = ?"
    with connect_app() as db:
        rows = db.execute(
            """SELECT a.*, u.email AS actor_email FROM audit_log a
               JOIN repairs r ON r.id = a.repair_id JOIN users u ON u.id = a.actor_id """
            + where_clause
            + " ORDER BY a.created_at DESC LIMIT 200",
            () if user["role"] == "admin" else (user["id"],),
        ).fetchall()
    return [dict(row) for row in rows]


@app.get("/api/reports")
def report(user: dict = Depends(current_user)):
    with connect_app() as db:
        totals = db.execute(
            """SELECT COUNT(*) AS analyses, COALESCE(SUM(tables_analyzed), 0) AS tables_analyzed,
                      COALESCE(AVG(health_score), 100) AS average_health
               FROM analyses WHERE owner_id = ?""",
            (user["id"],),
        ).fetchone()
        findings = db.execute(
            "SELECT status, severity, COUNT(*) AS count FROM findings WHERE owner_id = ? GROUP BY status, severity",
            (user["id"],),
        ).fetchall()
        repairs = db.execute(
            "SELECT status, COUNT(*) AS count FROM repairs WHERE owner_id = ? GROUP BY status",
            (user["id"],),
        ).fetchall()
        latest = db.execute(
            "SELECT * FROM analyses WHERE owner_id = ? ORDER BY created_at DESC LIMIT 1",
            (user["id"],),
        ).fetchone()
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "totals": dict(totals),
        "findings": [dict(row) for row in findings],
        "repairs": [dict(row) for row in repairs],
        "latest_analysis": dict(latest) if latest else None,
    }


def shutdown_engines():
    for engine in active_engines.values():
        engine.dispose()
