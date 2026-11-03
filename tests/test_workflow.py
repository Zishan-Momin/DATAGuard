import importlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from app import storage
from app.main import active_engines, app


class WorkflowTests(unittest.TestCase):
    def test_data_directory_environment_configures_both_databases(self):
        configured_dir = Path.cwd() / "configured-data-test"
        with patch.dict(os.environ, {"DBDIAG_DATA_DIR": str(configured_dir)}):
            importlib.reload(storage)
            self.assertEqual(storage.DATA_DIR, configured_dir.resolve())
            self.assertEqual(storage.APP_DB, configured_dir.resolve() / "app.db")
            self.assertEqual(storage.SAMPLE_DB, configured_dir.resolve() / "sample.db")

        importlib.reload(storage)

    def test_hosted_registration_requires_one_time_admin_setup_token(self):
        with tempfile.TemporaryDirectory() as directory:
            original_app_db, original_sample_db = storage.APP_DB, storage.SAMPLE_DB
            storage.APP_DB = Path(directory) / "app.db"
            storage.SAMPLE_DB = Path(directory) / "sample.db"
            try:
                with patch.dict(os.environ, {"DBDIAG_ADMIN_SETUP_TOKEN": "one-time-test-token"}):
                    with TestClient(app) as client:
                        viewer = client.post(
                            "/api/auth/register",
                            json={"email": "viewer@example.test", "password": "secure-viewer-password"},
                        )
                        self.assertEqual(viewer.status_code, 200, viewer.text)
                        self.assertEqual(viewer.json()["user"]["role"], "viewer")

                        admin = client.post(
                            "/api/auth/register",
                            json={
                                "email": "admin@example.test",
                                "password": "secure-admin-password",
                                "admin_setup_token": "one-time-test-token",
                            },
                        )
                        self.assertEqual(admin.status_code, 200, admin.text)
                        self.assertEqual(admin.json()["user"]["role"], "admin")

                        second_admin = client.post(
                            "/api/auth/register",
                            json={
                                "email": "second@example.test",
                                "password": "secure-second-password",
                                "admin_setup_token": "one-time-test-token",
                            },
                        )
                        self.assertEqual(second_admin.status_code, 200, second_admin.text)
                        self.assertEqual(second_admin.json()["user"]["role"], "viewer")
            finally:
                for engine in active_engines.values():
                    engine.dispose()
                active_engines.clear()
                storage.APP_DB, storage.SAMPLE_DB = original_app_db, original_sample_db

    def test_analysis_approval_execution_and_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            original_app_db, original_sample_db = storage.APP_DB, storage.SAMPLE_DB
            storage.APP_DB = Path(directory) / "app.db"
            storage.SAMPLE_DB = Path(directory) / "sample.db"
            try:
                with TestClient(app) as client:
                    page = client.get("/")
                    self.assertEqual(page.status_code, 200)
                    self.assertIn("Dataguard", page.text)
                    registration = client.post(
                        "/api/auth/register",
                        json={"email": "admin@example.test", "password": "secure-test-password"},
                    )
                    self.assertEqual(registration.status_code, 200, registration.text)
                    admin_headers = {"Authorization": f"Bearer {registration.json()['token']}"}

                    sample = client.post("/api/connections/sample", headers=admin_headers)
                    self.assertEqual(sample.status_code, 200, sample.text)
                    connection_id = sample.json()["id"]
                    schema = client.get(
                        f"/api/connections/{connection_id}/schema", headers=admin_headers
                    )
                    self.assertEqual(schema.status_code, 200, schema.text)
                    self.assertEqual({table["name"] for table in schema.json()["tables"]}, {"customers", "orders"})

                    analysis = client.post(f"/api/analysis/{connection_id}", headers=admin_headers)
                    self.assertEqual(analysis.status_code, 200, analysis.text)
                    self.assertEqual(analysis.json()["summary"]["detected"], 3)
                    index_finding = next(
                        finding for finding in analysis.json()["findings"]
                        if finding["repair_kind"] == "create_index"
                    )

                    proposal = client.post(
                        f"/api/findings/{index_finding['id']}/propose", headers=admin_headers
                    )
                    self.assertEqual(proposal.status_code, 200, proposal.text)
                    repair_id = proposal.json()["id"]
                    self.assertEqual(len(client.get("/api/repairs", headers=admin_headers).json()), 1)

                    viewer = client.post(
                        "/api/auth/register",
                        json={"email": "viewer@example.test", "password": "secure-viewer-password"},
                    )
                    self.assertEqual(viewer.status_code, 200, viewer.text)
                    viewer_headers = {"Authorization": f"Bearer {viewer.json()['token']}"}
                    forbidden = client.post(
                        f"/api/repairs/{repair_id}/decision",
                        headers=viewer_headers,
                        json={"decision": "approved"},
                    )
                    self.assertEqual(forbidden.status_code, 403)

                    refused = client.post(f"/api/repairs/{repair_id}/execute", headers=admin_headers)
                    self.assertEqual(refused.status_code, 409)

                    approved = client.post(
                        f"/api/repairs/{repair_id}/decision",
                        headers=admin_headers,
                        json={"decision": "approved"},
                    )
                    self.assertEqual(approved.status_code, 200, approved.text)
                    executed = client.post(f"/api/repairs/{repair_id}/execute", headers=admin_headers)
                    self.assertEqual(executed.status_code, 200, executed.text)
                    self.assertTrue(executed.json()["verified"])

                    repairs = client.get("/api/repairs", headers=admin_headers).json()
                    self.assertEqual(repairs[0]["status"], "executed")
                    self.assertEqual(client.get("/api/audit", headers=admin_headers).status_code, 200)
                    self.assertEqual(client.get("/api/reports", headers=admin_headers).status_code, 200)
            finally:
                for engine in active_engines.values():
                    engine.dispose()
                active_engines.clear()
                storage.APP_DB, storage.SAMPLE_DB = original_app_db, original_sample_db


if __name__ == "__main__":
    unittest.main()
