import pyotp
import io
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from PIL import Image
from sqlalchemy import select
from app.main import app
from app.auth import token_hash
from app.database import SessionLocal
from app.models import ApiToken, AuditEvent, ImageArchive, Scan


def test_local_setup_totp_session_csrf_and_recovery():
    with TestClient(app) as client:
        assert client.get("/api/auth/status").json()["configured"] is False
        assert client.get("/api/openapi.json").status_code == 401
        assert client.get("/docs").status_code == 404

        setup = client.post("/api/auth/setup", json={
            "display_name": "Local Admin", "username": "admin", "password": "correct horse battery staple"
        })
        assert setup.status_code == 201
        enrollment = setup.json()
        totp = pyotp.parse_uri(enrollment["otpauth_uri"])
        assert totp.issuer == "LayerScope"
        initial_code = totp.now()

        verified = client.post("/api/auth/totp/verify", json={
            "code": initial_code, "csrf_token": enrollment["csrf_token"]
        })
        assert verified.status_code == 200
        auth = verified.json()
        assert auth["user"]["role"] == "admin"
        assert len(auth["recovery_codes"]) == 10
        csrf = auth["csrf_token"]

        assert client.get("/api/auth/me").status_code == 200
        schema_response = client.get("/api/openapi.json")
        assert schema_response.status_code == 200
        schema = schema_response.json()
        assert schema["info"]["title"] == "LayerScope API"
        assert set(schema["components"]["securitySchemes"]) == {"BearerAuth", "SessionCookie"}
        assert schema["paths"]["/api/auth/status"]["get"]["security"] == []
        assert schema["paths"]["/api/users"]["get"]["x-layerscope-roles"] == ["admin"]
        assert schema["paths"]["/api/api-tokens"]["post"]["x-layerscope-authentication"] == "browser-session-only"
        assert schema["paths"]["/api/scans"]["post"]["x-layerscope-roles"] == ["admin", "operator"]
        assert "multipart/form-data" in schema["paths"]["/api/uploads"]["post"]["requestBody"]["content"]
        assert "application/json" in schema["paths"]["/api/reports/import"]["post"]["requestBody"]["content"]
        branded_operation = schema["paths"]["/api/exports/branded"]["post"]
        assert set(branded_operation["requestBody"]["content"]) == {"image/png", "image/jpeg"}
        assert branded_operation["x-layerscope-roles"] == ["admin", "operator", "viewer"]
        assert "/api/openapi.json" not in schema["paths"]
        backup = client.post("/api/backups/export", headers={"X-CSRF-Token": csrf},
                             json={"password": "portable backup passphrase 2026"})
        assert backup.status_code == 201
        assert backup.json()["filename"].startswith("layerscope-")
        download = client.get(f"/api/backups/download/{backup.json()['token']}")
        assert download.status_code == 200
        assert download.content.startswith(b"TRIVYDBBACKUP")
        staged = client.post("/api/backups/import", headers={"X-CSRF-Token": csrf},
                             files={"file": ("round-trip.tdbackup", download.content, "application/octet-stream")},
                             data={"password": "portable backup passphrase 2026"})
        assert staged.status_code == 201
        assert staged.json()["summary"]["users"] == 1
        assert client.delete(f"/api/backups/{staged.json()['token']}",
                             headers={"X-CSRF-Token": csrf}).status_code == 200
        wrong_password = client.post("/api/backups/import", headers={"X-CSRF-Token": csrf},
                                     files={"file": ("round-trip.tdbackup", download.content, "application/octet-stream")},
                                     data={"password": "incorrect backup passphrase"})
        assert wrong_password.status_code == 400
        assert client.post("/api/discover").status_code == 403
        assert client.post("/api/exports/branded?scan_ids=1&format=html",
                           headers={"Content-Type": "image/png"}, content=b"invalid").status_code == 403
        rejected_logo = client.post("/api/exports/branded?scan_ids=1&format=html",
                                    headers={"X-CSRF-Token": csrf, "Content-Type": "image/png"},
                                    content=b"not-a-png")
        assert rejected_logo.status_code == 400
        assert "signature" in rejected_logo.json()["detail"]
        with SessionLocal() as db:
            branding_event = db.scalar(select(AuditEvent).where(
                AuditEvent.action == "branded_report_export").order_by(AuditEvent.id.desc()))
            assert branding_event.outcome == "denied"
            assert "not-a-png" not in branding_event.details
            image = ImageArchive(path="/images/branded-export-test.tar", name="branded-export-test.tar",
                                 size=1, modified_at=datetime.now(timezone.utc))
            db.add(image); db.flush()
            scan = Scan(image_id=image.id, status="completed", progress=100,
                        finished_at=datetime.now(timezone.utc))
            db.add(scan); db.commit(); image_id, scan_id = image.id, scan.id
        logo = io.BytesIO()
        Image.new("RGB", (120, 40), (15, 40, 80)).save(logo, format="PNG")
        branded = client.post(f"/api/exports/branded?scan_ids={scan_id}&format=html",
                              headers={"X-CSRF-Token": csrf, "Content-Type": "image/png"},
                              content=logo.getvalue())
        assert branded.status_code == 200
        assert "data:image/png;base64," in branded.text
        with SessionLocal() as db:
            success_event = db.scalar(select(AuditEvent).where(
                AuditEvent.action == "branded_report_export").order_by(AuditEvent.id.desc()))
            assert success_event.outcome == "success"
            assert "source_logo_bytes" in success_event.details
            db.delete(db.get(ImageArchive, image_id)); db.commit()
        assert client.post("/api/discover", headers={"X-CSRF-Token": csrf}).status_code == 200
        invalid_report = client.post("/api/reports/import", headers={
            "X-CSRF-Token": csrf, "Content-Type": "application/json"}, content=b"{}")
        assert invalid_report.status_code == 400

        issued = client.post("/api/api-tokens", headers={"X-CSRF-Token": csrf}, json={
            "name": "Synthetic CI client", "expires_in_days": 30
        })
        assert issued.status_code == 201
        issued_payload = issued.json()
        raw_api_token = issued_payload["token"]
        assert raw_api_token.startswith("lsp_")
        listed = client.get("/api/api-tokens").json()
        assert listed[0]["name"] == "Synthetic CI client"
        assert "token" not in listed[0] and "token_hash" not in listed[0]
        with SessionLocal() as db:
            stored = db.get(ApiToken, issued_payload["id"])
            assert stored.token_hash == token_hash(raw_api_token)
            assert raw_api_token not in stored.token_hash

        token_client = TestClient(app)
        bearer = {"Authorization": f"Bearer {raw_api_token}"}
        token_me = token_client.get("/api/auth/me", headers=bearer)
        assert token_me.status_code == 200
        assert token_me.json()["auth_method"] == "api_token"
        assert token_me.json()["csrf_token"] == ""
        assert token_client.get("/api/users", headers=bearer).status_code == 200
        assert token_client.get("/api/openapi.json", headers=bearer).status_code == 200
        assert token_client.post("/api/discover", headers=bearer).status_code == 200
        assert token_client.post("/api/api-tokens", headers=bearer, json={
            "name": "Forbidden replacement", "expires_in_days": 30
        }).status_code == 403
        assert client.get("/api/auth/me", headers=bearer).status_code == 400
        assert client.delete(f"/api/api-tokens/{issued_payload['id']}",
                             headers={"X-CSRF-Token": csrf}).status_code == 200
        assert token_client.get("/api/auth/me", headers=bearer).status_code == 401
        token_client.close()

        created = client.post("/api/users", headers={"X-CSRF-Token": csrf}, json={
            "display_name": "Security Analyst", "username": "analyst", "role": "operator"
        })
        assert created.status_code == 201
        pending = created.json()
        assert pending["user"]["status"] == "pending_activation"
        assert pending["user"]["totp_enabled"] is False
        assert len(pending["activation_code"]) >= 20
        assert all("activation_code" not in item for item in client.get("/api/users").json())
        renamed = client.post(f"/api/users/{pending['user']['id']}/update",
                              headers={"X-CSRF-Token": csrf}, json={"display_name": "Senior Security Analyst"})
        assert renamed.status_code == 200
        assert renamed.json()["display_name"] == "Senior Security Analyst"

        disposable = client.post("/api/users", headers={"X-CSRF-Token": csrf}, json={
            "display_name": "Disposable User", "username": "disposable", "role": "viewer"
        })
        assert disposable.status_code == 201
        assert client.delete(f"/api/users/{auth['user']['id']}", headers={"X-CSRF-Token": csrf}).status_code == 409
        removed = client.delete(f"/api/users/{disposable.json()['user']['id']}", headers={"X-CSRF-Token": csrf})
        assert removed.status_code == 200
        assert removed.json()["username"] == "disposable"
        assert all(item["username"] != "disposable" for item in client.get("/api/users").json())
        assert client.delete("/api/scans/999999", headers={"X-CSRF-Token": csrf}).status_code == 404
        assert client.post("/api/scans/bulk-delete", headers={"X-CSRF-Token": csrf},
                           json={"scan_ids": [999998, 999999]}).status_code == 404
        assert client.delete("/api/images/999999", headers={"X-CSRF-Token": csrf}).status_code == 404
        assert client.post("/api/images/bulk-delete", headers={"X-CSRF-Token": csrf},
                           json={"image_ids": [999998, 999999]}).status_code == 404
        assert client.get("/api/images/999999/archive").status_code == 404
        created_group = client.post("/api/groups", headers={"X-CSRF-Token": csrf}, json={
            "name": "Admin group", "description": "Created by an administrator", "color": "blue"
        })
        assert created_group.status_code == 201
        assert client.post(f"/api/groups/{created_group.json()['id']}/members",
                           headers={"X-CSRF-Token": csrf}, json={"image_ids": []}).status_code == 200
        assert client.post(f"/api/groups/{created_group.json()['id']}/members/add",
                           headers={"X-CSRF-Token": csrf}, json={"image_ids": []}).status_code == 400

        self_demotion = client.post(f"/api/users/{auth['user']['id']}/update",
                                    headers={"X-CSRF-Token": csrf}, json={"role": "viewer"})
        assert self_demotion.status_code == 409
        assert client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf}).status_code == 200
        assert client.get("/api/auth/me").status_code == 401

        login = client.post("/api/auth/login", json={"username": "admin", "password": "correct horse battery staple"})
        assert login.status_code == 200
        challenge = login.json()

        replayed_totp = client.post("/api/auth/totp/verify", json={
            "code": initial_code, "csrf_token": challenge["csrf_token"]
        })
        assert replayed_totp.status_code == 401

        recovery = client.post("/api/auth/totp/verify", json={
            "code": auth["recovery_codes"][0], "csrf_token": challenge["csrf_token"]
        })
        assert recovery.status_code == 200
        assert recovery.json()["recovery_code_used"] is True

        client.post("/api/auth/logout", headers={"X-CSRF-Token": recovery.json()["csrf_token"]})
        login_again = client.post("/api/auth/login", json={"username": "admin", "password": "correct horse battery staple"}).json()
        reused = client.post("/api/auth/totp/verify", json={
            "code": auth["recovery_codes"][0], "csrf_token": login_again["csrf_token"]
        })
        assert reused.status_code == 401

        activated = client.post("/api/auth/activate", json={
            "username": "analyst", "activation_code": pending["activation_code"],
            "password": "private ocean lantern passphrase 2026"
        })
        assert activated.status_code == 200
        analyst_enrollment = activated.json()
        analyst_totp = pyotp.parse_uri(analyst_enrollment["otpauth_uri"])
        analyst_verified = client.post("/api/auth/totp/verify", json={
            "code": analyst_totp.now(), "csrf_token": analyst_enrollment["csrf_token"]
        })
        assert analyst_verified.status_code == 200
        analyst_auth = analyst_verified.json()
        assert analyst_auth["user"]["role"] == "operator"
        assert analyst_auth["user"]["totp_enabled"] is True

        assert client.get("/api/users").status_code == 403
        forbidden_create = client.post("/api/users", headers={"X-CSRF-Token": analyst_auth["csrf_token"]}, json={
            "display_name": "Forbidden User", "username": "forbidden", "role": "viewer"
        })
        assert forbidden_create.status_code == 403
        assert client.delete("/api/scans/999999", headers={"X-CSRF-Token": analyst_auth["csrf_token"]}).status_code == 403
        assert client.post("/api/scans/bulk-delete", headers={"X-CSRF-Token": analyst_auth["csrf_token"]},
                           json={"scan_ids": [999999]}).status_code == 403
        assert client.post("/api/backups/export", headers={"X-CSRF-Token": analyst_auth["csrf_token"]},
                           json={"password": "operator backup passphrase"}).status_code == 403
        assert client.post("/api/reports/import", headers={
            "X-CSRF-Token": analyst_auth["csrf_token"], "Content-Type": "application/json"},
            content=b"{}").status_code == 403
        assert client.delete("/api/images/999999", headers={"X-CSRF-Token": analyst_auth["csrf_token"]}).status_code == 403
        assert client.post("/api/images/bulk-delete", headers={"X-CSRF-Token": analyst_auth["csrf_token"]},
                           json={"image_ids": [999999]}).status_code == 403
        assert client.post("/api/groups", headers={"X-CSRF-Token": analyst_auth["csrf_token"],}, json={
            "name": "Operator group", "description": "Operators can organize images", "color": "emerald"
        }).status_code == 201
        assert client.delete(f"/api/users/{auth['user']['id']}",
                             headers={"X-CSRF-Token": analyst_auth["csrf_token"]}).status_code == 403

        assert client.post("/api/auth/logout", headers={"X-CSRF-Token": analyst_auth["csrf_token"]}).status_code == 200
        admin_login = client.post("/api/auth/login", json={
            "username": "admin", "password": "correct horse battery staple"
        }).json()
        admin_verified = client.post("/api/auth/totp/verify", json={
            "code": auth["recovery_codes"][1], "csrf_token": admin_login["csrf_token"]
        })
        assert admin_verified.status_code == 200
        admin_csrf = admin_verified.json()["csrf_token"]
        reissued = client.post(f"/api/users/{analyst_auth['user']['id']}/reissue-2fa",
                               headers={"X-CSRF-Token": admin_csrf})
        assert reissued.status_code == 200
        assert len(reissued.json()["reissue_code"]) >= 20
        assert "password" not in reissued.json()
        assert client.post(f"/api/users/{auth['user']['id']}/reissue-2fa",
                           headers={"X-CSRF-Token": admin_csrf}).status_code == 409
        assert client.post("/api/auth/logout", headers={"X-CSRF-Token": admin_csrf}).status_code == 200

        reenrollment = client.post("/api/auth/reenroll-2fa", json={
            "username": "analyst", "password": "private ocean lantern passphrase 2026",
            "reissue_code": reissued.json()["reissue_code"]
        })
        assert reenrollment.status_code == 200
        new_totp = pyotp.parse_uri(reenrollment.json()["otpauth_uri"])
        reenrolled = client.post("/api/auth/totp/verify", json={
            "code": new_totp.now(), "csrf_token": reenrollment.json()["csrf_token"]
        })
        assert reenrolled.status_code == 200
        assert reenrolled.json()["user"]["role"] == "operator"
        assert len(reenrolled.json()["recovery_codes"]) == 10
        consumed = client.post("/api/auth/reenroll-2fa", json={
            "username": "analyst", "password": "private ocean lantern passphrase 2026",
            "reissue_code": reissued.json()["reissue_code"]
        })
        assert consumed.status_code == 401
        assert client.post("/api/auth/setup", json={
            "display_name": "Second Bootstrap", "username": "bootstrap", "password": "another safe passphrase 2026"
        }).status_code == 409
