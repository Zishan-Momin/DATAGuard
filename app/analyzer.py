from collections import Counter
from contextlib import contextmanager

from sqlalchemy import inspect
from sqlalchemy.engine import Engine


@contextmanager
def _read_only_connection(engine: Engine):
    with engine.connect() as connection:
        if engine.dialect.name == "sqlite":
            connection.exec_driver_sql("PRAGMA query_only = ON")
        elif engine.dialect.name in ("postgresql", "mysql"):
            connection.exec_driver_sql("SET TRANSACTION READ ONLY")
        try:
            yield connection
        finally:
            if engine.dialect.name == "sqlite":
                connection.exec_driver_sql("PRAGMA query_only = OFF")


def _quote(engine: Engine, identifier: str) -> str:
    return engine.dialect.identifier_preparer.quote(identifier)


def analyze_database(engine: Engine) -> dict:
    findings: list[dict] = []
    table_stats: list[dict] = []

    with _read_only_connection(engine) as connection:
        inspector = inspect(connection)
        table_names = inspector.get_table_names()
        for table_name in table_names:
            columns = inspector.get_columns(table_name)
            column_names = [column["name"] for column in columns]
            primary_columns = set(inspector.get_pk_constraint(table_name).get("constrained_columns") or [])
            quoted_table = _quote(engine, table_name)
            count = connection.exec_driver_sql(f"SELECT COUNT(*) FROM {quoted_table}").scalar_one()
            table_stats.append({"name": table_name, "rows": count, "columns": len(columns)})

            for column in columns:
                if column.get("nullable", True):
                    quoted_column = _quote(engine, column["name"])
                    null_count = connection.exec_driver_sql(
                        f"SELECT COUNT(*) FROM {quoted_table} WHERE {quoted_column} IS NULL"
                    ).scalar_one()
                    if null_count:
                        findings.append(
                            {
                                "name": f"NULL values in {table_name}.{column['name']}",
                                "category": "Data quality",
                                "severity": "Medium",
                                "status": "detected",
                                "table_name": table_name,
                                "column_name": column["name"],
                                "description": f"{null_count} of {count} rows have no value in {column['name']}.",
                                "root_cause": "The column permits NULL values and the data-entry path did not provide a value.",
                                "recommendation": "Confirm whether the field is required, then validate new writes and backfill existing rows before considering a NOT NULL constraint.",
                                "impact": "Reports, filters, and application logic may handle these rows inconsistently.",
                                "risk": "Backfilling or constraining values can change application behavior; review data first.",
                                "repair_kind": None,
                            }
                        )

            duplicate_columns = [name for name in column_names if name not in primary_columns]
            if duplicate_columns:
                group_columns = ", ".join(_quote(engine, name) for name in duplicate_columns)
                duplicate = connection.exec_driver_sql(
                    f"SELECT COUNT(*) FROM (SELECT 1 FROM {quoted_table} GROUP BY {group_columns} HAVING COUNT(*) > 1)"
                ).scalar_one()
                if duplicate:
                    findings.append(
                        {
                            "name": f"Duplicate rows in {table_name}",
                            "category": "Data quality",
                            "severity": "High",
                            "status": "detected",
                            "table_name": table_name,
                            "column_name": None,
                            "description": f"{duplicate} groups of identical rows were found across all columns.",
                            "root_cause": "No uniqueness rule prevents identical records, or records were imported more than once.",
                            "recommendation": "Review duplicate groups, decide which record is authoritative, and add an appropriate uniqueness rule after cleanup.",
                            "impact": "Counts and downstream aggregates may be inflated.",
                            "risk": "Removing duplicates could discard valid data; no automatic cleanup is offered.",
                            "repair_kind": None,
                        }
                    )

            for foreign_key in inspector.get_foreign_keys(table_name):
                constrained = foreign_key.get("constrained_columns") or []
                if not constrained:
                    continue
                indexes = inspector.get_indexes(table_name)
                primary = primary_columns
                indexed = primary | {
                    column
                    for index in indexes
                    if index.get("column_names")
                    for column in index["column_names"][:1]
                }
                for column_name in constrained:
                    if column_name in indexed:
                        continue
                    index_name = f"ix_{table_name}_{column_name}"
                    findings.append(
                        {
                            "name": f"Missing index on {table_name}.{column_name}",
                            "category": "Performance",
                            "severity": "Medium",
                            "status": "potential",
                            "table_name": table_name,
                            "column_name": column_name,
                            "description": f"Foreign-key column {column_name} has no index; joins and parent-row checks may scan the table.",
                            "root_cause": "The schema defines a foreign key but no index begins with the constrained column.",
                            "recommendation": f"Create an index on {table_name}.{column_name} and compare query plans for representative workloads.",
                            "impact": "Can reduce lookup and join work as the table grows.",
                            "risk": "Indexes consume storage and add write overhead.",
                            "repair_kind": "create_index",
                            "index_name": index_name,
                        }
                    )

        if engine.dialect.name == "sqlite":
            violations = connection.exec_driver_sql("PRAGMA foreign_key_check").fetchall()
            for table_name, rowid, parent, fk_id in violations:
                findings.append(
                    {
                        "name": f"Foreign-key violation in {table_name}",
                        "category": "Integrity",
                        "severity": "High",
                        "status": "detected",
                        "table_name": table_name,
                        "column_name": None,
                        "description": f"SQLite found a row ({rowid}) in {table_name} without a matching parent in {parent}.",
                        "root_cause": "A write bypassed or predated enforcement of the declared foreign key.",
                        "recommendation": "Identify the owning application workflow and correct or quarantine the orphan after business review.",
                        "impact": "Related records may not resolve correctly.",
                        "risk": "Changing or deleting the orphan can affect business data; no automatic cleanup is offered.",
                        "repair_kind": None,
                    }
                )

    severity_weights = {"Critical": 25, "High": 15, "Medium": 8, "Low": 3}
    score = max(0, 100 - sum(severity_weights.get(item["severity"], 0) for item in findings if item["status"] == "detected"))
    categories = Counter(item["category"] for item in findings)
    severities = Counter(item["severity"] for item in findings)
    return {
        "tables": table_stats,
        "findings": findings,
        "health_score": score,
        "summary": {
            "detected": sum(item["status"] == "detected" for item in findings),
            "potential": sum(item["status"] == "potential" for item in findings),
            "categories": dict(categories),
            "severities": dict(severities),
        },
    }


def build_index_sql(engine: Engine, table_name: str, column_name: str, index_name: str) -> str:
    inspector = inspect(engine)
    if table_name not in inspector.get_table_names():
        raise ValueError("The affected table no longer exists.")
    valid_columns = {column["name"] for column in inspector.get_columns(table_name)}
    if column_name not in valid_columns:
        raise ValueError("The affected column no longer exists.")
    expected_name = f"ix_{table_name}_{column_name}"
    if index_name != expected_name:
        raise ValueError("The proposed index does not match the approved finding.")
    quote = engine.dialect.identifier_preparer.quote
    return f"CREATE INDEX {quote(index_name)} ON {quote(table_name)} ({quote(column_name)})"
