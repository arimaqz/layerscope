import json
import io
import asyncio
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi import HTTPException, Request
from PIL import Image, PngImagePlugin
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.main import export_reports, read_report_logo
from app.models import Finding, ImageArchive, ImageGroup, ImageGroupMember, Package, Scan
from app.reports import (ELASTIC_ECS_VERSION, ELASTIC_INDEX, MAX_REPORT_LOGO_BYTES, REPORT_PATH_PREFIX,
                         GroupExportError, ReportImportError, ReportLogoError, defectdojo_payload,
                         group_export_selection, import_report_payload, normalize_import_payload,
                         render_elastic_bulk, render_html, render_pdf, report_payload, sanitize_report_logo)


def isolated_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)()


def test_html_report_has_distinct_styles_for_every_severity():
    severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
    payload = {"generated_at": datetime.now(timezone.utc), "reports": [{
        "image": "example.tar", "total": len(severities), "scan_id": 1, "status": "completed", "finished_at": datetime.now(timezone.utc),
        "counts": {severity: 1 for severity in severities},
        "findings": [{"severity": severity, "vulnerability_id": f"CVE-{index}", "package": "package",
                      "installed_version": "1", "fixed_version": "2", "target": "image", "title": "Finding"}
                     for index, severity in enumerate(severities)],
    }]}

    report = render_html(payload)

    for severity in severities:
        assert f"class='pill {severity.lower()}'" in report
    assert "LAYERSCOPE" in report
    assert ".high{background:#fef2f2" in report
    assert ".medium{background:#fff7ed" in report
    assert ".low{background:#eff6ff" in report
    assert "/data/uploads" not in report

    pdf = render_pdf(payload)
    assert pdf.startswith(b"%PDF")
    assert len(pdf) > 2_000


def png_bytes(size=(320, 100), *, metadata=False, animated=False):
    output = io.BytesIO()
    image = Image.new("RGBA", size, (15, 40, 80, 255))
    info = None
    if metadata:
        info = PngImagePlugin.PngInfo()
        info.add_text("Comment", "<script>alert('metadata')</script>")
    if animated:
        second = Image.new("RGBA", size, (80, 40, 15, 255))
        image.save(output, format="PNG", save_all=True, append_images=[second], duration=100, loop=0)
    else:
        image.save(output, format="PNG", pnginfo=info)
    return output.getvalue()


def jpeg_bytes(size=(320, 100)):
    output = io.BytesIO()
    Image.new("RGB", size, (15, 40, 80)).save(output, format="JPEG", quality=85)
    return output.getvalue()


def test_report_logo_is_strictly_validated_reencoded_and_embedded_only_when_requested():
    source = png_bytes(metadata=True)
    sanitized = sanitize_report_logo(source, "image/png")

    assert sanitized.startswith(b"\x89PNG\r\n\x1a\n")
    assert b"<script>" not in sanitized
    assert len(sanitized) < len(source)
    assert sanitize_report_logo(jpeg_bytes(), "image/jpeg").startswith(b"\x89PNG\r\n\x1a\n")

    payload = portable_payload()
    unbranded = render_html(payload)
    branded = render_html(payload, sanitized)
    assert "data:image/png;base64," not in unbranded
    assert "data:image/png;base64," in branded
    assert "Custom report logo" in branded
    assert "max-width:340px;max-height:110px" in branded
    assert "background:#fff;padding:12px" in branded
    assert render_pdf(payload, sanitized).startswith(b"%PDF")

    invalid = [
        (b"<svg xmlns='http://www.w3.org/2000/svg'></svg>", "image/png"),
        (png_bytes() + b"<html>trailing polyglot</html>", "image/png"),
        (png_bytes(), "image/jpeg"),
        (png_bytes(size=(2001, 1)), "image/png"),
        (png_bytes(animated=True), "image/png"),
        (b"x" * (MAX_REPORT_LOGO_BYTES + 1), "image/png"),
    ]
    for data, content_type in invalid:
        with pytest.raises(ReportLogoError):
            sanitize_report_logo(data, content_type)


def test_report_logo_request_stream_enforces_content_type_and_encoded_limit():
    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    def request(content_type: str, content_length: int):
        return Request({"type": "http", "method": "POST", "path": "/api/exports/branded",
                        "headers": [(b"content-type", content_type.encode()),
                                    (b"content-length", str(content_length).encode())]}, receive)

    with pytest.raises(HTTPException) as unsupported:
        asyncio.run(read_report_logo(request("image/svg+xml", 10)))
    assert unsupported.value.status_code == 415
    with pytest.raises(HTTPException) as oversized:
        asyncio.run(read_report_logo(request("image/png", MAX_REPORT_LOGO_BYTES + 1)))
    assert oversized.value.status_code == 413


def portable_payload():
    db = isolated_session()
    image = ImageArchive(path="/images/example.tar", name="example.tar", size=2048,
                         modified_at=datetime.now(timezone.utc))
    db.add(image); db.flush()
    scan = Scan(image_id=image.id, status="completed", progress=100, stage="completed",
                started_at=datetime(2026, 8, 20, 10, 0, tzinfo=timezone.utc),
                finished_at=datetime(2026, 8, 20, 10, 2, tzinfo=timezone.utc))
    db.add(scan); db.flush()
    db.add(Finding(scan_id=scan.id, target="debian", vulnerability_id="CVE-2026-0001",
                   package_name="example-package", installed_version="1.0", fixed_version="1.1",
                   severity="HIGH", title="Synthetic finding", description="Synthetic description",
                   primary_url="https://security.example/CVE-2026-0001"))
    db.add(Package(scan_id=scan.id, target="debian", name="example-package", version="1.0",
                   identifier="pkg:deb/example-package@1.0", licenses="MIT"))
    db.commit()
    payload = report_payload(db, [scan.id])
    return json.loads(json.dumps(payload, default=str))


def golden_payload():
    return {"generated_at": "2026-08-21T12:00:00Z", "reports": [{
        "scan_id": 7, "image_id": 3, "image_key": "a" * 64, "image": "example-image.tar",
        "finished_at": "2026-08-20T10:02:00Z", "findings": [{
            "vulnerability_id": "CVE-2026-0001", "severity": "HIGH", "package": "example-package",
            "installed_version": "1.0", "fixed_version": "1.1", "target": "debian",
            "title": "Synthetic finding", "description": "Synthetic description",
            "primary_url": "https://security.example/CVE-2026-0001",
        }],
    }]}


def test_json_report_round_trip_restores_normalized_evidence_without_archive():
    payload = portable_payload()
    assert payload["format"] == "layerscope-report"
    assert payload["format_version"] == 1
    assert payload["reports"][0]["packages"][0]["identifier"] == "pkg:deb/example-package@1.0"

    restored = isolated_session()
    first = import_report_payload(restored, payload)
    restored.commit()

    image = restored.scalar(select(ImageArchive))
    scan = restored.scalar(select(Scan))
    assert first == {"imported_reports": 1, "skipped_duplicates": 0, "image_count": 1,
                     "findings": 1, "packages": 1}
    assert image.path.startswith(REPORT_PATH_PREFIX)
    assert image.size == 0
    assert scan.status == "completed"
    assert scan.stage == "imported_report"
    assert restored.scalar(select(func.count()).select_from(Finding)) == 1
    assert restored.scalar(select(func.count()).select_from(Package)) == 1

    reexported = report_payload(restored, [scan.id])
    assert reexported["reports"][0]["image_key"] == payload["reports"][0]["image_key"]

    duplicate = import_report_payload(restored, payload)
    restored.commit()
    assert duplicate["imported_reports"] == 0
    assert duplicate["skipped_duplicates"] == 1
    assert restored.scalar(select(func.count()).select_from(Scan)) == 1


def test_legacy_export_without_packages_imports_finding_package_fallback():
    payload = portable_payload()
    payload.pop("format"); payload.pop("format_version")
    payload["reports"][0].pop("image_key")
    payload["reports"][0].pop("packages")
    restored = isolated_session()

    result = import_report_payload(restored, payload)
    restored.commit()

    package = restored.scalar(select(Package))
    assert result["packages"] == 1
    assert package.name == "example-package"
    assert package.version == "1.0"


def test_report_import_rejects_tampered_counts_and_unexpected_fields():
    payload = portable_payload()
    payload["reports"][0]["counts"]["HIGH"] = 2
    with pytest.raises(ReportImportError, match="severity counts"):
        normalize_import_payload(payload)
    payload = portable_payload()
    payload["reports"][0]["findings"][0]["unsafe"] = "value"
    with pytest.raises(ReportImportError, match="unsupported fields"):
        normalize_import_payload(payload)


def test_group_export_uses_latest_visible_scans_once_and_reports_partial_coverage():
    db = isolated_session()
    first = ImageGroup(name="Production", description="", color="blue")
    second = ImageGroup(name="Shared", description="", color="emerald")
    db.add_all([first, second]); db.flush()
    scanned = ImageArchive(path="/images/scanned.tar", name="scanned.tar", size=1,
                           modified_at=datetime.now(timezone.utc))
    unscanned = ImageArchive(path="/images/unscanned.tar", name="unscanned.tar", size=1,
                             modified_at=datetime.now(timezone.utc))
    hidden = ImageArchive(path="/images/hidden.tar", name="hidden.tar", size=1,
                          modified_at=datetime.now(timezone.utc), hidden=True)
    db.add_all([scanned, unscanned, hidden]); db.flush()
    db.add_all([ImageGroupMember(group_id=first.id, image_id=scanned.id),
                ImageGroupMember(group_id=first.id, image_id=unscanned.id),
                ImageGroupMember(group_id=second.id, image_id=scanned.id),
                ImageGroupMember(group_id=second.id, image_id=hidden.id)])
    old = Scan(image_id=scanned.id, status="completed", progress=100,
               finished_at=datetime(2026, 8, 20, tzinfo=timezone.utc))
    db.add(old); db.flush()
    latest = Scan(image_id=scanned.id, status="completed", progress=100,
                  finished_at=datetime(2026, 8, 21, tzinfo=timezone.utc))
    hidden_scan = Scan(image_id=hidden.id, status="completed", progress=100,
                       finished_at=datetime(2026, 8, 21, tzinfo=timezone.utc))
    db.add_all([latest, hidden_scan]); db.commit()

    scan_ids, selection = group_export_selection(db, [first.id, second.id, first.id])

    assert scan_ids == [latest.id]
    assert selection["groups"] == [{"id": first.id, "name": "Production"},
                                   {"id": second.id, "name": "Shared"}]
    assert selection["member_count"] == 2
    assert selection["included_scan_count"] == 1
    assert selection["unscanned_member_count"] == 1
    assert selection["unscanned_members"] == [{"image_id": unscanned.id, "image": "unscanned.tar"}]

    payload = report_payload(db, scan_ids); payload["selection"] = selection
    assert normalize_import_payload(json.loads(json.dumps(payload, default=str)))
    assert "GROUP SNAPSHOT" in render_html(payload)
    assert "Production, Shared" in render_html(payload)
    assert render_pdf(payload).startswith(b"%PDF")
    elastic = render_elastic_bulk(payload)
    assert elastic == ""  # Compatibility streams contain findings rather than empty scan records.
    dojo = defectdojo_payload(payload)
    assert dojo["name"] == "LayerScope image-group vulnerability report"
    assert "Included 1 of 2" in dojo["description"]

    for report_format in ("json", "html", "pdf", "elastic", "defectdojo"):
        response = export_reports(None, [first.id, second.id], report_format, db)
        assert 'filename="layerscope-group-' in response.headers["content-disposition"]
    with pytest.raises(HTTPException) as mixed:
        export_reports([latest.id], [first.id], "json", db)
    assert mixed.value.status_code == 422


def test_group_export_rejects_missing_empty_and_entirely_unscanned_groups():
    db = isolated_session()
    empty = ImageGroup(name="Empty", description="", color="blue")
    unscanned = ImageGroup(name="Unscanned", description="", color="blue")
    image = ImageArchive(path="/images/example.tar", name="example.tar", size=1,
                         modified_at=datetime.now(timezone.utc))
    db.add_all([empty, unscanned, image]); db.flush()
    db.add(ImageGroupMember(group_id=unscanned.id, image_id=image.id)); db.commit()

    with pytest.raises(GroupExportError, match="not found") as missing:
        group_export_selection(db, [999])
    assert missing.value.status_code == 404
    with pytest.raises(GroupExportError, match="no visible image members") as no_members:
        group_export_selection(db, [empty.id])
    assert no_members.value.status_code == 409
    with pytest.raises(GroupExportError, match="completed scan") as no_scans:
        group_export_selection(db, [unscanned.id])
    assert no_scans.value.status_code == 409

def test_elastic_bulk_export_is_ecs_ndjson_with_stable_privacy_safe_ids():
    payload = portable_payload()
    payload["generated_at"] = "2026-08-21T12:00:00+00:00"
    payload["selection"] = {"type": "groups", "groups": [{"id": 4, "name": "Production"}],
                            "member_count": 1, "included_scan_count": 1, "unscanned_member_count": 0,
                            "unscanned_members": [], "unscanned_members_truncated": False}

    first = render_elastic_bulk(payload)
    second = render_elastic_bulk(payload)
    lines = first.splitlines()

    assert first == second
    assert first.endswith("\n")
    assert len(lines) == 2
    action, document = map(json.loads, lines)
    assert action["index"]["_index"] == ELASTIC_INDEX
    assert action["index"]["_id"] == document["event"]["id"]
    assert document["ecs"]["version"] == ELASTIC_ECS_VERSION
    assert document["@timestamp"] == "2026-08-20T10:02:00Z"
    assert document["event"]["category"] == ["vulnerability"]
    assert document["vulnerability"]["severity"] == "High"
    assert document["container"]["image"]["name"] == "example.tar"
    assert document["package"] == {"name": "example-package", "version": "1.0"}
    assert document["layerscope"]["group_ids"] == [4]
    assert document["layerscope"]["group_names"] == ["Production"]
    assert "/images/example.tar" not in first


def test_defectdojo_export_uses_generic_findings_contract_and_maps_unknown_to_info():
    payload = portable_payload()
    payload["generated_at"] = "2026-08-21T12:00:00+00:00"
    unknown = dict(payload["reports"][0]["findings"][0])
    unknown.update({"vulnerability_id": "VENDOR-UNKNOWN-1", "severity": "UNKNOWN", "primary_url": ""})
    payload["reports"][0]["findings"].append(unknown)

    exported = defectdojo_payload(payload)

    assert exported["type"] == "LayerScope"
    assert exported["name"] == "LayerScope container vulnerability report"
    assert len(exported["findings"]) == 2
    high, info = exported["findings"]
    assert high["severity"] == "High"
    assert high["vulnerability_ids"] == ["CVE-2026-0001"]
    assert high["component_name"] == "example-package"
    assert high["fix_available"] is True
    assert info["severity"] == "Info"
    assert "UNKNOWN severity" in info["severity_justification"]
    assert high["unique_id_from_tool"] != info["unique_id_from_tool"]
    assert "/images/example.tar" not in json.dumps(exported)

    payload["reports"][0]["image"] = "i" * 240
    payload["reports"][0]["findings"][0].update({
        "title": "t" * 4_000, "package": "p" * 500,
        "installed_version": "v" * 500, "fixed_version": "f" * 1_000,
    })
    bounded = defectdojo_payload(payload)["findings"][0]
    assert len(bounded["title"]) == 511
    assert len(bounded["service"]) == 200
    assert len(bounded["component_name"]) == 500
    assert len(bounded["component_version"]) == 100
    assert len(bounded["fix_version"]) == 100


def test_compatibility_exports_match_golden_synthetic_fixtures():
    fixtures = Path(__file__).parent / "fixtures"

    assert render_elastic_bulk(golden_payload()) == (fixtures / "elastic-export.ndjson").read_text(encoding="utf-8")
    assert defectdojo_payload(golden_payload()) == json.loads(
        (fixtures / "defectdojo-export.json").read_text(encoding="utf-8"))
