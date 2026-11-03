import os
import sqlite3
from contextlib import closing, contextmanager
from pathlib import Path

from app.security import hash_password


ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("DBDIAG_DATA_DIR", ROOT / "data")).expanduser().resolve()
APP_DB = DATA_DIR / "app.db"
SAMPLE_DB = DATA_DIR / "sample.db"


@contextmanager
def connect_app():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(APP_DB)
    connection.row_factory = sqlite3.Row
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def init_storage() -> None:
    with connect_app() as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('admin', 'viewer')),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS connections (
                id TEXT PRIMARY KEY,
                owner_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                backend TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS analyses (
                id TEXT PRIMARY KEY,
                connection_id TEXT NOT NULL,
                owner_id INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                tables_analyzed INTEGER NOT NULL,
                health_score INTEGER NOT NULL,
                summary_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                analysis_id TEXT NOT NULL,
                connection_id TEXT NOT NULL,
                owner_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                category TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL,
                table_name TEXT,
                column_name TEXT,
                description TEXT NOT NULL,
                root_cause TEXT NOT NULL,
                recommendation TEXT NOT NULL,
                impact TEXT NOT NULL,
                risk TEXT NOT NULL,
                repair_kind TEXT,
                repair_status TEXT NOT NULL DEFAULT 'not_proposed',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS repairs (
                id TEXT PRIMARY KEY,
                finding_id TEXT NOT NULL,
                connection_id TEXT NOT NULL,
                owner_id INTEGER NOT NULL,
                requested_by INTEGER NOT NULL,
                status TEXT NOT NULL,
                approved_by INTEGER,
                sql_preview TEXT NOT NULL,
                execution_result TEXT,
                error_detail TEXT,
                verified INTEGER,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                repair_id TEXT NOT NULL,
                actor_id INTEGER NOT NULL,
                action TEXT NOT NULL,
                detail TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            """
        )


def seed_sample() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(SAMPLE_DB)) as db:
        db.execute("PRAGMA foreign_keys = OFF")
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS customers (
                id INTEGER PRIMARY KEY,
                email TEXT,
                full_name TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS orders (
                id INTEGER PRIMARY KEY,
                customer_id INTEGER NOT NULL,
                amount REAL NOT NULL,
                FOREIGN KEY(customer_id) REFERENCES customers(id)
            );
            DROP INDEX IF EXISTS ix_orders_customer_id;
            DELETE FROM orders;
            DELETE FROM customers;
            INSERT INTO customers(id, email, full_name) VALUES
                (1, 'alex@example.test', 'Alex Morgan'),
                (2, 'alex@example.test', 'Alex Morgan'),
                (3, NULL, 'Jamie Lee'),
                (4, 'sam@example.test', 'Sam Rivera');
            INSERT INTO orders(id, customer_id, amount) VALUES
                (10, 1, 25.50),
                (11, 999, 13.00),
                (12, 3, 42.00);
            """
        )
