import tempfile
import unittest
from pathlib import Path

from sqlalchemy import create_engine

from app.analyzer import analyze_database, build_index_sql
from app.main import make_engine


class AnalyzerTests(unittest.TestCase):
    def test_seeded_sample_detects_actual_data_issues_and_index_candidate(self):
        from app.storage import seed_sample, SAMPLE_DB

        seed_sample()
        engine = create_engine(f"sqlite:///{SAMPLE_DB.as_posix()}")
        result = analyze_database(engine)
        names = [finding["name"] for finding in result["findings"]]
        self.assertIn("Duplicate rows in customers", names)
        self.assertIn("NULL values in customers.email", names)
        self.assertIn("Foreign-key violation in orders", names)
        self.assertIn("Missing index on orders.customer_id", names)
        self.assertEqual(result["summary"]["detected"], 3)
        self.assertEqual(result["summary"]["potential"], 1)
        engine.dispose()

    def test_index_sql_is_built_from_existing_identifiers(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "db.sqlite"
            engine = create_engine(f"sqlite:///{path.as_posix()}")
            with engine.begin() as connection:
                connection.exec_driver_sql("CREATE TABLE parent (id INTEGER PRIMARY KEY)")
                connection.exec_driver_sql(
                    "CREATE TABLE child (id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES parent(id))"
                )
            sql = build_index_sql(engine, "child", "parent_id", "ix_child_parent_id")
            self.assertEqual(sql, "CREATE INDEX ix_child_parent_id ON child (parent_id)")
            with self.assertRaises(ValueError):
                build_index_sql(engine, "child", "parent_id", "ix_child_parent_id; DROP TABLE child")
            engine.dispose()

    def test_custom_sqlite_connection_uses_supplied_path(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "local.sqlite")
            engine = make_engine("SQLite", path)
            with engine.connect() as connection:
                self.assertEqual(connection.exec_driver_sql("SELECT 1").scalar_one(), 1)
            engine.dispose()


if __name__ == "__main__":
    unittest.main()
