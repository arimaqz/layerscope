import io
import base64
import hashlib
import json
import re
from datetime import datetime, timezone
from html import escape

from PIL import Image as PillowImage, ImageOps, UnidentifiedImageError

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import Image as ReportImage
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from sqlalchemy import distinct, func, select
from sqlalchemy.orm import Session, selectinload

from .models import Finding, ImageArchive, ImageGroup, ImageGroupMember, Package, Scan
from .scanner import bulk_insert_models
from .security import safe_advisory_url


SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
SEVERITY_ORDER = {value: index for index, value in enumerate(SEVERITIES)}
SEVERITY_PALETTE = {
    "CRITICAL": ("#fee2e2", "#7f1d1d", "#991b1b"),
    "HIGH": ("#fef2f2", "#b91c1c", "#dc2626"),
    "MEDIUM": ("#fff7ed", "#c2410c", "#f97316"),
    "LOW": ("#eff6ff", "#1d4ed8", "#2563eb"),
    "UNKNOWN": ("#f1f5f9", "#475569", "#64748b"),
}
PDF_FONT = "Helvetica"
REPORT_FORMAT = "layerscope-report"
REPORT_FORMAT_VERSION = 1
REPORT_PATH_PREFIX = "report://"
REPORT_SCAN_PREFIX = "report-import:"
ELASTIC_ECS_VERSION = "9.5.0"
ELASTIC_INDEX = "layerscope-vulnerabilities"
DEFECTDOJO_TYPE = "LayerScope"
MAX_REPORTS = 100
MAX_FINDINGS = 250_000
MAX_PACKAGES = 500_000
MAX_UNSCANNED_SAMPLE = 100
MAX_REPORT_LOGO_BYTES = 2 * 1024 * 1024
MAX_REPORT_LOGO_WIDTH = 2000
MAX_REPORT_LOGO_HEIGHT = 1000
MAX_REPORT_LOGO_PIXELS = 2_000_000
MAX_SANITIZED_LOGO_BYTES = 8 * 1024 * 1024
HEX_KEY = re.compile(r"^[0-9a-f]{64}$")
try:
    pdfmetrics.registerFont(TTFont("DejaVuSans", "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"))
    pdfmetrics.registerFont(TTFont("DejaVuSans-Bold", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"))
    PDF_FONT = "DejaVuSans"
except (OSError, IOError):
    pass


class GroupExportError(ValueError):
    def __init__(self, status_code: int, message: str):
        super().__init__(message)
        self.status_code = status_code


class ReportLogoError(ValueError):
    pass


def _strict_png_container(data: bytes) -> bool:
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return False
    offset = 8
    while offset + 12 <= len(data):
        length = int.from_bytes(data[offset:offset + 4], "big")
        chunk_type = data[offset + 4:offset + 8]
        end = offset + 12 + length
        if end > len(data):
            return False
        offset = end
        if chunk_type == b"IEND":
            return length == 0 and offset == len(data)
    return False


def sanitize_report_logo(data: bytes, content_type: str) -> bytes:
    """Decode, validate, and metadata-strip an untrusted per-export report logo."""
    if not data:
        raise ReportLogoError("The report logo is empty")
    if len(data) > MAX_REPORT_LOGO_BYTES:
        raise ReportLogoError(f"The report logo exceeds the {MAX_REPORT_LOGO_BYTES // (1024 * 1024)} MiB limit")
    declared = content_type.split(";", 1)[0].strip().casefold()
    if declared not in {"image/png", "image/jpeg"}:
        raise ReportLogoError("Report logos must be PNG or JPEG images")
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        detected = "image/png"
        if not _strict_png_container(data):
            raise ReportLogoError("The PNG logo is malformed or contains trailing data")
    elif data.startswith(b"\xff\xd8\xff"):
        detected = "image/jpeg"
        if not data.endswith(b"\xff\xd9"):
            raise ReportLogoError("The JPEG logo is malformed or contains trailing data")
    else:
        raise ReportLogoError("The report logo does not have a supported PNG or JPEG signature")
    if declared != detected:
        raise ReportLogoError("The report logo content type does not match its encoded format")
    try:
        with PillowImage.open(io.BytesIO(data)) as image:
            if image.format not in {"PNG", "JPEG"} or getattr(image, "is_animated", False) or getattr(image, "n_frames", 1) != 1:
                raise ReportLogoError("Animated or unsupported report logos are not allowed")
            width, height = image.size
            if (width < 1 or height < 1 or width > MAX_REPORT_LOGO_WIDTH or height > MAX_REPORT_LOGO_HEIGHT
                    or width * height > MAX_REPORT_LOGO_PIXELS):
                raise ReportLogoError(
                    f"Report logos are limited to {MAX_REPORT_LOGO_WIDTH}x{MAX_REPORT_LOGO_HEIGHT} and "
                    f"{MAX_REPORT_LOGO_PIXELS:,} decoded pixels"
                )
            image.verify()
        with PillowImage.open(io.BytesIO(data)) as image:
            image.load()
            normalized = ImageOps.exif_transpose(image)
            normalized = normalized.convert("RGBA" if "A" in normalized.getbands() else "RGB")
            output = io.BytesIO()
            normalized.save(output, format="PNG", compress_level=6)
            sanitized = output.getvalue()
    except ReportLogoError:
        raise
    except (UnidentifiedImageError, PillowImage.DecompressionBombError, OSError, SyntaxError, ValueError) as exc:
        raise ReportLogoError("The report logo could not be decoded safely") from exc
    if len(sanitized) > MAX_SANITIZED_LOGO_BYTES:
        raise ReportLogoError("The decoded report logo is too complex")
    return sanitized


def group_export_selection(db: Session, group_ids: list[int]) -> tuple[list[int], dict]:
    """Resolve the latest completed scan for every visible member without per-image queries."""
    unique_group_ids = list(dict.fromkeys(group_ids))
    if not unique_group_ids or len(unique_group_ids) > MAX_REPORTS or any(group_id < 1 for group_id in unique_group_ids):
        raise GroupExportError(422, f"Export between 1 and {MAX_REPORTS} valid group IDs")

    groups = db.execute(select(ImageGroup.id, ImageGroup.name).where(ImageGroup.id.in_(unique_group_ids))).all()
    groups_by_id = {row.id: row.name for row in groups}
    missing = [group_id for group_id in unique_group_ids if group_id not in groups_by_id]
    if missing:
        raise GroupExportError(404, f"Image group not found: {missing[0]}")

    members = (select(distinct(ImageGroupMember.image_id).label("image_id"))
               .join(ImageArchive, ImageArchive.id == ImageGroupMember.image_id)
               .where(ImageGroupMember.group_id.in_(unique_group_ids), ImageArchive.hidden.is_(False))
               .subquery())
    member_count = db.scalar(select(func.count()).select_from(members)) or 0
    if member_count == 0:
        raise GroupExportError(409, "The selected group export has no visible image members")

    latest = (select(Scan.image_id.label("image_id"), func.max(Scan.id).label("scan_id"))
              .join(members, members.c.image_id == Scan.image_id)
              .where(Scan.status == "completed")
              .group_by(Scan.image_id).subquery())
    scan_rows = db.execute(
        select(latest.c.scan_id, ImageArchive.id, ImageArchive.name)
        .join(ImageArchive, ImageArchive.id == latest.c.image_id)
        .order_by(func.lower(ImageArchive.name), ImageArchive.id)
        .limit(MAX_REPORTS + 1)
    ).all()
    if not scan_rows:
        raise GroupExportError(409, "No visible member in the selected group export has a completed scan")
    if len(scan_rows) > MAX_REPORTS:
        raise GroupExportError(422, f"Group exports are limited to {MAX_REPORTS} completed image reports")

    unscanned_rows = db.execute(
        select(ImageArchive.id, ImageArchive.name)
        .join(members, members.c.image_id == ImageArchive.id)
        .outerjoin(latest, latest.c.image_id == ImageArchive.id)
        .where(latest.c.scan_id.is_(None))
        .order_by(func.lower(ImageArchive.name), ImageArchive.id)
        .limit(MAX_UNSCANNED_SAMPLE)
    ).all()
    unscanned_count = member_count - len(scan_rows)
    selection = {
        "type": "groups",
        "groups": [{"id": group_id, "name": groups_by_id[group_id]} for group_id in unique_group_ids],
        "member_count": member_count,
        "included_scan_count": len(scan_rows),
        "unscanned_member_count": unscanned_count,
        "unscanned_members": [{"image_id": row.id, "image": row.name} for row in unscanned_rows],
        "unscanned_members_truncated": unscanned_count > len(unscanned_rows),
    }
    return [row.scan_id for row in scan_rows], selection


def report_payload(db: Session, scan_ids: list[int]) -> dict:
    scans = {scan.id: scan for scan in db.scalars(
        select(Scan).options(selectinload(Scan.image)).where(Scan.id.in_(scan_ids))).all()}
    found_by_scan: dict[int, list[Finding]] = {}
    package_by_scan: dict[int, list[Package]] = {}
    if scans:
        scan_keys = list(scans)
        for finding in db.scalars(select(Finding).where(Finding.scan_id.in_(scan_keys))).all():
            found_by_scan.setdefault(finding.scan_id, []).append(finding)
        for package in db.scalars(select(Package).where(Package.scan_id.in_(scan_keys))).all():
            package_by_scan.setdefault(package.scan_id, []).append(package)
    reports = []
    for scan_id in scan_ids:
        scan = scans.get(scan_id)
        if not scan:
            continue
        findings = found_by_scan.get(scan.id, [])
        items = [{
            "vulnerability_id": finding.vulnerability_id, "severity": finding.severity,
            "package": finding.package_name, "installed_version": finding.installed_version,
            "fixed_version": finding.fixed_version, "target": finding.target, "title": finding.title,
            "description": finding.description, "primary_url": finding.primary_url,
        } for finding in sorted(findings, key=lambda item: (
            SEVERITY_ORDER.get(item.severity, 4), item.package_name.casefold(), item.vulnerability_id))]
        counts = {severity: 0 for severity in SEVERITIES}
        for item in items:
            severity = item["severity"] if item["severity"] in counts else "UNKNOWN"
            counts[severity] += 1
        packages = [{
            "name": package.name, "version": package.version, "target": package.target,
            "identifier": package.identifier, "licenses": package.licenses,
        } for package in sorted(package_by_scan.get(scan.id, []), key=lambda item: (
            item.name.casefold(), item.version, item.target))]
        reports.append({
            "scan_id": scan.id, "image_id": scan.image.id,
            "image_key": portable_image_key_for_archive(scan.image), "image": scan.image.name,
            "status": scan.status, "started_at": scan.started_at, "finished_at": scan.finished_at,
            "coverage_warning": scan.coverage_warning, "counts": counts, "total": len(items),
            "findings": items, "packages": packages,
        })
    return {"format": REPORT_FORMAT, "format_version": REPORT_FORMAT_VERSION,
            "generated_at": datetime.now(timezone.utc), "report_count": len(reports), "reports": reports}


def _utc_timestamp(value: datetime | str | None, fallback: datetime | str) -> str:
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if value is None:
        value = fallback
        if isinstance(value, str):
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _finding_identity(report: dict, finding: dict) -> str:
    finished_at = _utc_timestamp(report.get("finished_at"), report.get("generated_at") or datetime.now(timezone.utc))
    values = (report.get("image_key", ""), finished_at, finding.get("vulnerability_id", ""),
              finding.get("package", ""), finding.get("installed_version", ""), finding.get("target", ""))
    return hashlib.sha256("\0".join(str(value) for value in values).encode("utf-8")).hexdigest()


def render_elastic_bulk(payload: dict) -> str:
    """Return ECS 9.5.0 events in Elasticsearch Bulk API NDJSON form."""
    lines = []
    generated_at = payload.get("generated_at") or datetime.now(timezone.utc)
    for report in payload.get("reports", []):
        timestamp = _utc_timestamp(report.get("finished_at"), generated_at)
        report_id = hashlib.sha256(f"{report.get('image_key', '')}\0{timestamp}".encode("utf-8")).hexdigest()
        for finding in report.get("findings", []):
            document_id = _finding_identity({**report, "generated_at": generated_at}, finding)
            vulnerability_id = str(finding.get("vulnerability_id", ""))
            enumeration = vulnerability_id.split("-", 1)[0].upper() if "-" in vulnerability_id else "OTHER"
            document = {
                "@timestamp": timestamp,
                "ecs": {"version": ELASTIC_ECS_VERSION},
                "event": {"id": document_id, "kind": "state", "category": ["vulnerability"],
                          "type": ["info"], "action": "vulnerability-detected",
                          "module": "layerscope", "dataset": "layerscope.vulnerability"},
                "observer": {"vendor": "LayerScope", "product": "LayerScope"},
                "container": {"image": {"name": report.get("image", "")}},
                "package": {"name": finding.get("package", ""), "version": finding.get("installed_version", "")},
                "vulnerability": {
                    "id": vulnerability_id,
                    "enumeration": enumeration,
                    "classification": enumeration,
                    "severity": str(finding.get("severity", "UNKNOWN")).title(),
                    "description": finding.get("description") or finding.get("title") or vulnerability_id,
                    "report_id": report_id,
                    "scanner": {"vendor": "Aqua Security"},
                },
                "message": finding.get("title") or vulnerability_id,
                "layerscope": {
                    "image_key": report.get("image_key", ""), "scan_id": report.get("scan_id"),
                    "target": finding.get("target", ""), "fixed_version": finding.get("fixed_version", ""),
                    "fix_available": bool(finding.get("fixed_version")),
                },
            }
            selection = payload.get("selection")
            if selection and selection.get("type") == "groups":
                document["layerscope"]["group_ids"] = [group["id"] for group in selection["groups"]]
                document["layerscope"]["group_names"] = [group["name"] for group in selection["groups"]]
                document["layerscope"]["group_member_count"] = selection["member_count"]
                document["layerscope"]["group_included_scan_count"] = selection["included_scan_count"]
                document["layerscope"]["group_unscanned_member_count"] = selection["unscanned_member_count"]
            if finding.get("primary_url"):
                document["vulnerability"]["reference"] = finding["primary_url"]
            lines.append(json.dumps({"index": {"_index": ELASTIC_INDEX, "_id": document_id}}, ensure_ascii=False,
                                   separators=(",", ":")))
            lines.append(json.dumps(document, ensure_ascii=False, separators=(",", ":")))
    return "\n".join(lines) + ("\n" if lines else "")


def defectdojo_payload(payload: dict) -> dict:
    """Return DefectDojo Generic Findings Import JSON."""
    findings = []
    generated_at = payload.get("generated_at") or datetime.now(timezone.utc)
    severity_map = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low", "UNKNOWN": "Info"}
    for report in payload.get("reports", []):
        timestamp = _utc_timestamp(report.get("finished_at"), generated_at)
        for finding in report.get("findings", []):
            original_severity = str(finding.get("severity", "UNKNOWN")).upper()
            vulnerability_id = str(finding.get("vulnerability_id", ""))
            package_name = str(finding.get("package", ""))
            description = finding.get("description") or finding.get("title") or vulnerability_id
            item = {
                "title": str(finding.get("title") or f"{vulnerability_id} in {package_name}")[:511],
                "severity": severity_map.get(original_severity, "Info"),
                "description": description,
                "date": timestamp[:10],
                "active": True,
                "verified": False,
                "static_finding": True,
                "dynamic_finding": False,
                "component_name": package_name[:500],
                "component_version": str(finding.get("installed_version", ""))[:100],
                "file_path": finding.get("target", ""),
                "service": str(report.get("image", ""))[:200],
                "vuln_id_from_tool": vulnerability_id,
                "unique_id_from_tool": _finding_identity({**report, "generated_at": generated_at}, finding),
                "vulnerability_ids": [vulnerability_id],
                "fix_available": bool(finding.get("fixed_version")),
                "fix_version": str(finding.get("fixed_version", ""))[:100],
                "references": finding.get("primary_url", ""),
                "tags": ["layerscope", "container-image", f"layerscope-severity:{original_severity.lower()}"],
            }
            if original_severity == "UNKNOWN":
                item["severity_justification"] = "LayerScope UNKNOWN severity mapped to DefectDojo Info."
            findings.append(item)
    selection = payload.get("selection")
    group_names = [group["name"] for group in selection["groups"]] if selection and selection.get("type") == "groups" else []
    name = "LayerScope container vulnerability report"
    description = "Normalized LayerScope findings for DefectDojo Generic Findings Import."
    if group_names:
        name = "LayerScope image-group vulnerability report"
        description = (f"Latest completed LayerScope scans for image groups: {', '.join(group_names)}. "
                       f"Included {selection['included_scan_count']} of {selection['member_count']} visible members; "
                       f"{selection['unscanned_member_count']} had no completed scan.")
    return {
        "name": name,
        "type": DEFECTDOJO_TYPE,
        "version": "1.0.0",
        "description": description,
        "findings": findings,
    }


class ReportImportError(ValueError):
    pass


def portable_image_key(image_id: int, image_name: str) -> str:
    return hashlib.sha256(f"{image_id}\0{image_name}".encode("utf-8")).hexdigest()


def portable_image_key_for_archive(image: ImageArchive) -> str:
    if is_report_path(image.path):
        key = image.path.removeprefix(REPORT_PATH_PREFIX)
        if HEX_KEY.fullmatch(key):
            return key
    return portable_image_key(image.id, image.name)


def is_report_path(path: str) -> bool:
    return path.startswith(REPORT_PATH_PREFIX)


def is_imported_scan(scan: Scan) -> bool:
    return bool(scan.raw_json_path and scan.raw_json_path.startswith(REPORT_SCAN_PREFIX))


def _text(value, field: str, maximum: int, required: bool = False) -> str:
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise ReportImportError(f"{field} must be text")
    if len(value) > maximum:
        raise ReportImportError(f"{field} is too long")
    if any(ord(character) < 32 and character not in "\t\n\r" for character in value):
        raise ReportImportError(f"{field} contains control characters")
    if required and not value.strip():
        raise ReportImportError(f"{field} is required")
    return value


def _time(value, field: str, required: bool = False) -> datetime | None:
    if value in (None, ""):
        if required:
            raise ReportImportError(f"{field} is required")
        return None
    if not isinstance(value, str):
        raise ReportImportError(f"{field} must be an ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReportImportError(f"{field} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    parsed = parsed.astimezone(timezone.utc)
    if not 2000 <= parsed.year <= 2200:
        raise ReportImportError(f"{field} is outside the supported date range")
    return parsed


def _keys(value: dict, allowed: set[str], field: str):
    unexpected = set(value) - allowed
    if unexpected:
        raise ReportImportError(f"{field} contains unsupported fields")


def normalize_import_payload(payload: object) -> list[dict]:
    if not isinstance(payload, dict):
        raise ReportImportError("The report file must contain a JSON object")
    _keys(payload, {"format", "format_version", "generated_at", "report_count", "reports", "selection"}, "Report file")
    if payload.get("format") not in (None, REPORT_FORMAT):
        raise ReportImportError("This is not a LayerScope report export")
    if payload.get("format_version") not in (None, REPORT_FORMAT_VERSION):
        raise ReportImportError("This report format version is not supported")
    reports = payload.get("reports")
    if not isinstance(reports, list) or not 1 <= len(reports) <= MAX_REPORTS:
        raise ReportImportError(f"Import between 1 and {MAX_REPORTS} reports at a time")
    if payload.get("report_count") is not None and payload["report_count"] != len(reports):
        raise ReportImportError("The report count does not match the report contents")
    generated_at = _time(payload.get("generated_at"), "generated_at")
    if payload.get("selection") is not None:
        _validate_group_selection(payload["selection"])
        if payload["selection"]["included_scan_count"] != len(reports):
            raise ReportImportError("Report selection included scan count does not match the report contents")
    normalized, finding_count, package_count = [], 0, 0
    report_fields = {"scan_id", "image_id", "image_key", "image", "status", "started_at", "finished_at",
                     "coverage_warning", "counts", "total", "findings", "packages"}
    finding_fields = {"vulnerability_id", "severity", "package", "installed_version", "fixed_version",
                      "target", "title", "description", "primary_url"}
    package_fields = {"name", "version", "target", "identifier", "licenses"}
    for index, raw_report in enumerate(reports, start=1):
        if not isinstance(raw_report, dict):
            raise ReportImportError(f"Report {index} must be an object")
        _keys(raw_report, report_fields, f"Report {index}")
        if raw_report.get("status") != "completed":
            raise ReportImportError(f"Report {index} is not a completed scan")
        image = _text(raw_report.get("image"), f"Report {index} image", 240, required=True).strip()
        if "/" in image or "\\" in image or image in {".", ".."}:
            raise ReportImportError(f"Report {index} image name is invalid")
        image_id = raw_report.get("image_id")
        if not isinstance(image_id, int) or isinstance(image_id, bool) or image_id < 1:
            raise ReportImportError(f"Report {index} image_id is invalid")
        image_key = raw_report.get("image_key") or portable_image_key(image_id, image)
        if not isinstance(image_key, str) or not HEX_KEY.fullmatch(image_key):
            raise ReportImportError(f"Report {index} image_key is invalid")
        findings_raw = raw_report.get("findings")
        if not isinstance(findings_raw, list):
            raise ReportImportError(f"Report {index} findings must be a list")
        finding_count += len(findings_raw)
        if finding_count > MAX_FINDINGS:
            raise ReportImportError(f"Report imports are limited to {MAX_FINDINGS:,} findings")
        findings = []
        counts = {severity: 0 for severity in SEVERITIES}
        for raw_finding in findings_raw:
            if not isinstance(raw_finding, dict):
                raise ReportImportError(f"Report {index} contains an invalid finding")
            _keys(raw_finding, finding_fields, f"Report {index} finding")
            severity = _text(raw_finding.get("severity"), "Finding severity", 20).upper()
            severity = severity if severity in SEVERITY_ORDER else "UNKNOWN"
            finding = {
                "vulnerability_id": _text(raw_finding.get("vulnerability_id"), "Finding vulnerability_id", 200, True),
                "severity": severity, "package": _text(raw_finding.get("package"), "Finding package", 500),
                "installed_version": _text(raw_finding.get("installed_version"), "Finding installed_version", 500),
                "fixed_version": _text(raw_finding.get("fixed_version"), "Finding fixed_version", 1000),
                "target": _text(raw_finding.get("target"), "Finding target", 2000),
                "title": _text(raw_finding.get("title"), "Finding title", 4000),
                "description": _text(raw_finding.get("description"), "Finding description", 100_000),
                "primary_url": safe_advisory_url(_text(raw_finding.get("primary_url"), "Finding primary_url", 2048)),
            }
            counts[severity] += 1
            findings.append(finding)
        if raw_report.get("total") is not None and raw_report["total"] != len(findings):
            raise ReportImportError(f"Report {index} finding total does not match its contents")
        supplied_counts = raw_report.get("counts")
        if supplied_counts is not None:
            if not isinstance(supplied_counts, dict) or set(supplied_counts) - set(SEVERITIES) or any(
                    supplied_counts.get(severity, 0) != counts[severity] for severity in SEVERITIES):
                raise ReportImportError(f"Report {index} severity counts do not match its findings")
        packages_raw = raw_report.get("packages")
        packages = []
        if packages_raw is not None:
            if not isinstance(packages_raw, list):
                raise ReportImportError(f"Report {index} packages must be a list")
            package_count += len(packages_raw)
            if package_count > MAX_PACKAGES:
                raise ReportImportError(f"Report imports are limited to {MAX_PACKAGES:,} packages")
            for raw_package in packages_raw:
                if not isinstance(raw_package, dict):
                    raise ReportImportError(f"Report {index} contains an invalid package")
                _keys(raw_package, package_fields, f"Report {index} package")
                packages.append({
                    "name": _text(raw_package.get("name"), "Package name", 500, True),
                    "version": _text(raw_package.get("version"), "Package version", 500),
                    "target": _text(raw_package.get("target"), "Package target", 2000),
                    "identifier": _text(raw_package.get("identifier"), "Package identifier", 4000),
                    "licenses": _text(raw_package.get("licenses"), "Package licenses", 4000),
                })
        else:
            package_keys = {(item["package"], item["installed_version"], item["target"]) for item in findings if item["package"]}
            packages = [{"name": name, "version": version, "target": target, "identifier": "", "licenses": ""}
                        for name, version, target in sorted(package_keys)]
            package_count += len(packages)
            if package_count > MAX_PACKAGES:
                raise ReportImportError(f"Report imports are limited to {MAX_PACKAGES:,} packages")
        started_at = _time(raw_report.get("started_at"), f"Report {index} started_at")
        finished_at = _time(raw_report.get("finished_at"), f"Report {index} finished_at", required=True)
        coverage_warning = _text(raw_report.get("coverage_warning"), f"Report {index} coverage_warning", 4000)
        normalized_report = {"image": image, "image_key": image_key, "started_at": started_at,
                             "finished_at": finished_at, "generated_at": generated_at,
                             "coverage_warning": coverage_warning, "findings": findings, "packages": packages}
        fingerprint_value = json.dumps(normalized_report, default=str, sort_keys=True,
                                       ensure_ascii=False, separators=(",", ":"))
        normalized_report["fingerprint"] = hashlib.sha256(fingerprint_value.encode("utf-8")).hexdigest()
        normalized.append(normalized_report)
    return normalized


def _validate_group_selection(selection: object) -> None:
    if not isinstance(selection, dict):
        raise ReportImportError("Report selection must be an object")
    _keys(selection, {"type", "groups", "member_count", "included_scan_count", "unscanned_member_count",
                      "unscanned_members", "unscanned_members_truncated"}, "Report selection")
    if selection.get("type") != "groups":
        raise ReportImportError("Report selection type is not supported")
    groups = selection.get("groups")
    if not isinstance(groups, list) or not 1 <= len(groups) <= MAX_REPORTS:
        raise ReportImportError("Report selection groups are invalid")
    seen_groups = set()
    for group in groups:
        if not isinstance(group, dict):
            raise ReportImportError("Report selection contains an invalid group")
        _keys(group, {"id", "name"}, "Report selection group")
        if not isinstance(group.get("id"), int) or isinstance(group.get("id"), bool) or group["id"] < 1:
            raise ReportImportError("Report selection group ID is invalid")
        if group["id"] in seen_groups:
            raise ReportImportError("Report selection contains a duplicate group")
        seen_groups.add(group["id"])
        _text(group.get("name"), "Report selection group name", 100, True)
    counts = [selection.get(key) for key in ("member_count", "included_scan_count", "unscanned_member_count")]
    if any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in counts):
        raise ReportImportError("Report selection counts are invalid")
    if counts[1] + counts[2] != counts[0]:
        raise ReportImportError("Report selection counts do not match")
    members = selection.get("unscanned_members")
    if not isinstance(members, list) or len(members) > MAX_UNSCANNED_SAMPLE:
        raise ReportImportError("Report selection unscanned members are invalid")
    for member in members:
        if not isinstance(member, dict):
            raise ReportImportError("Report selection contains an invalid unscanned member")
        _keys(member, {"image_id", "image"}, "Report selection unscanned member")
        if not isinstance(member.get("image_id"), int) or isinstance(member.get("image_id"), bool) or member["image_id"] < 1:
            raise ReportImportError("Report selection unscanned member ID is invalid")
        _text(member.get("image"), "Report selection unscanned member image", 240, True)
    if not isinstance(selection.get("unscanned_members_truncated"), bool):
        raise ReportImportError("Report selection truncation flag is invalid")


def import_report_payload(db: Session, payload: object) -> dict:
    reports = normalize_import_payload(payload)
    fingerprints = [REPORT_SCAN_PREFIX + report["fingerprint"] for report in reports]
    existing = set(db.scalars(select(Scan.raw_json_path).where(Scan.raw_json_path.in_(fingerprints))).all())
    imported_scans = skipped = findings_added = packages_added = 0
    touched_images: set[int] = set()
    for report in reports:
        marker = REPORT_SCAN_PREFIX + report["fingerprint"]
        if marker in existing:
            skipped += 1
            continue
        path = REPORT_PATH_PREFIX + report["image_key"]
        image = db.scalar(select(ImageArchive).where(ImageArchive.path == path))
        if image is None:
            image = ImageArchive(path=path, name=report["image"], size=0,
                                 modified_at=report["finished_at"], discovered_at=datetime.now(timezone.utc))
            db.add(image)
            db.flush()
        elif image.name != report["image"]:
            raise ReportImportError("An imported report image key conflicts with a different image name")
        scan = Scan(image_id=image.id, status="completed", progress=100, stage="imported_report",
                    message="Imported portable report; original image archive is not included",
                    queued_at=report["started_at"] or report["finished_at"], started_at=report["started_at"],
                    finished_at=report["finished_at"], updated_at=datetime.now(timezone.utc),
                    raw_json_path=marker, coverage_warning=report["coverage_warning"] or None)
        db.add(scan)
        db.flush()
        findings = [Finding(scan_id=scan.id, target=item["target"], vulnerability_id=item["vulnerability_id"],
                            package_name=item["package"], installed_version=item["installed_version"],
                            fixed_version=item["fixed_version"], severity=item["severity"], title=item["title"],
                            description=item["description"], primary_url=item["primary_url"])
                    for item in report["findings"]]
        packages = [Package(scan_id=scan.id, target=item["target"], name=item["name"], version=item["version"],
                            identifier=item["identifier"], licenses=item["licenses"])
                    for item in report["packages"]]
        bulk_insert_models(db, Finding, findings)
        bulk_insert_models(db, Package, packages)
        imported_scans += 1
        findings_added += len(findings)
        packages_added += len(packages)
        touched_images.add(image.id)
        existing.add(marker)
    return {"imported_reports": imported_scans, "skipped_duplicates": skipped,
            "image_count": len(touched_images), "findings": findings_added, "packages": packages_added}


def format_time(value) -> str:
    if not value:
        return "Not available"
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return str(value)


def aggregate_counts(payload: dict):
    return {severity: sum(report["counts"].get(severity, 0) for report in payload["reports"])
            for severity in SEVERITIES}


def group_selection_html(payload: dict) -> str:
    selection = payload.get("selection")
    if not selection or selection.get("type") != "groups":
        return ""
    names = ", ".join(escape(group["name"]) for group in selection["groups"])
    missing = selection["unscanned_member_count"]
    samples = ", ".join(escape(member["image"]) for member in selection["unscanned_members"])
    suffix = " and more" if selection["unscanned_members_truncated"] else ""
    detail = f"<p><b>{missing}</b> visible member(s) had no completed scan and were not included"
    if samples:
        detail += f": {samples}{suffix}"
    return ("<section class='selection'><span class='eyebrow'>GROUP SNAPSHOT</span>"
            f"<h2>{names}</h2><p><b>{selection['included_scan_count']}</b> of "
            f"<b>{selection['member_count']}</b> visible members included.</p>{detail}.</p></section>")


def render_html(payload: dict, logo_png: bytes | None = None) -> str:
    report_count = payload.get("report_count", len(payload["reports"]))
    totals = aggregate_counts(payload)
    overview = "".join(summary_card(severity, totals[severity]) for severity in SEVERITIES)
    sections = []
    for report in payload["reports"]:
        rows = "".join(render_html_finding(finding) for finding in report["findings"])
        if not rows:
            rows = "<tr><td colspan='7' class='empty'>No vulnerabilities were recorded.</td></tr>"
        counts = "".join(summary_card(severity, report["counts"].get(severity, 0)) for severity in SEVERITIES)
        sections.append(
            f"<section class='report'><div class='report-head'><div><span class='eyebrow'>IMAGE REPORT</span>"
            f"<h2>{escape(report['image'])}</h2></div><div class='scan-meta'><b>Scan #{report['scan_id']}</b>"
            f"<span>{escape(format_time(report['finished_at']))}</span></div></div>"
            f"<div class='severity-grid'>{counts}</div><div class='meta-row'><span><b>{report['total']}</b> total findings</span>"
            f"<span>Status: <b>{escape(str(report['status']).title())}</b></span></div>"
            "<div class='table-wrap'><table><thead><tr><th>Severity</th><th>Vulnerability</th><th>Package</th>"
            "<th>Installed</th><th>Fixed version</th><th>Target</th><th>Title</th></tr></thead>"
            f"<tbody>{rows}</tbody></table></div></section>"
        )
    generated = escape(format_time(payload["generated_at"]))
    selection = group_selection_html(payload)
    logo_html = ""
    if logo_png:
        encoded_logo = base64.b64encode(logo_png).decode("ascii")
        logo_html = f"<img class='brand-logo' src='data:image/png;base64,{encoded_logo}' alt='Custom report logo'>"
    brand_class = "brand-lockup branded" if logo_png else "brand-lockup"
    return f"""<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width'>
<title>Container vulnerability report</title><style>
:root{{--navy:#0f172a;--slate:#475569;--line:#dbe3ee;--canvas:#f4f7fb}}*{{box-sizing:border-box}}body{{margin:0;background:var(--canvas);color:#172033;font:14px/1.45 Inter,ui-sans-serif,system-ui,sans-serif}}.hero{{background:linear-gradient(135deg,#0f172a,#1e3a8a);color:white;padding:38px max(28px,calc((100vw - 1380px)/2))}}.hero h1{{font-size:30px;margin:4px 0}}.hero p{{margin:0;color:#bfdbfe}}.brand-lockup.branded{{display:flex;align-items:center;gap:26px}}.brand-logo{{display:block;max-width:340px;max-height:110px;width:auto;height:auto;object-fit:contain;background:#fff;padding:12px;border:1px solid rgba(255,255,255,.85);border-radius:14px;box-shadow:0 8px 24px rgba(15,23,42,.32)}}.eyebrow{{font-size:11px;font-weight:800;letter-spacing:.16em;color:#60a5fa}}main{{max-width:1380px;margin:0 auto;padding:28px}}.overview,.selection,.report{{background:white;border:1px solid var(--line);border-radius:16px;box-shadow:0 8px 28px rgba(15,23,42,.06)}}.overview,.selection{{padding:22px;margin-bottom:24px}}.selection p{{margin:7px 0 0;color:var(--slate)}}.overview-head,.report-head,.meta-row{{display:flex;align-items:center;justify-content:space-between;gap:20px}}h2{{font-size:22px;margin:4px 0}}.severity-grid{{display:grid;grid-template-columns:repeat(5,minmax(120px,1fr));gap:10px;margin-top:18px}}.metric{{border-radius:11px;padding:12px;border-left:4px solid #64748b;background:#f8fafc}}.metric b{{display:block;font-size:22px}}.metric span{{font-size:11px;font-weight:800;letter-spacing:.05em}}.metric.critical{{background:#fee2e2;color:#7f1d1d;border-color:#991b1b}}.metric.high{{background:#fef2f2;color:#b91c1c;border-color:#dc2626}}.metric.medium{{background:#fff7ed;color:#c2410c;border-color:#f97316}}.metric.low{{background:#eff6ff;color:#1d4ed8;border-color:#2563eb}}.metric.unknown{{background:#f1f5f9;color:#475569;border-color:#64748b}}.report{{padding:24px;margin:24px 0;break-before:page}}.report:first-of-type{{break-before:auto}}.scan-meta{{display:flex;flex-direction:column;text-align:right;color:var(--slate)}}.meta-row{{margin:16px 0;color:var(--slate)}}.table-wrap{{overflow:auto;border:1px solid var(--line);border-radius:12px}}table{{width:100%;border-collapse:collapse}}th{{position:sticky;top:0;background:#0f172a;color:white;font-size:11px;letter-spacing:.05em;text-transform:uppercase}}th,td{{padding:10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}}tbody tr:nth-child(even){{background:#f8fafc}}.pill{{display:inline-block;padding:4px 8px;border-radius:999px;font-size:11px;font-weight:800}}.critical{{background:#fee2e2;color:#7f1d1d}}.high{{background:#fef2f2;color:#b91c1c}}.medium{{background:#fff7ed;color:#c2410c}}.low{{background:#eff6ff;color:#1d4ed8}}.unknown{{background:#f1f5f9;color:#475569}}.empty{{padding:28px;text-align:center;color:#64748b}}@media(max-width:800px){{.brand-lockup.branded{{align-items:flex-start;flex-direction:column}}.brand-logo{{max-width:min(340px,100%)}}.severity-grid{{grid-template-columns:repeat(2,1fr)}}.overview-head,.report-head,.meta-row{{align-items:flex-start;flex-direction:column}}.scan-meta{{text-align:left}}main{{padding:16px}}}}@media print{{body{{background:white}}.hero{{padding:24px;background:#0f172a!important;-webkit-print-color-adjust:exact;print-color-adjust:exact}}main{{max-width:none;padding:12px}}.overview,.selection,.report{{box-shadow:none}}}}
</style></head><body><header class='hero'><div class='{brand_class}'>{logo_html}<div><span class='eyebrow'>LAYERSCOPE</span><h1>Container vulnerability report</h1><p>Generated {generated} · {report_count} image report(s)</p></div></div></header><main>{selection}<section class='overview'><div class='overview-head'><div><span class='eyebrow'>PORTFOLIO SUMMARY</span><h2>{sum(totals.values())} findings across {report_count} images</h2></div></div><div class='severity-grid'>{overview}</div></section>{''.join(sections)}</main></body></html>"""


def summary_card(severity: str, count: int) -> str:
    return f"<div class='metric {severity.lower()}'><span>{escape(severity)}</span><b>{count:,}</b></div>"


def render_html_finding(finding: dict) -> str:
    severity = str(finding.get("severity") or "UNKNOWN").upper()
    if severity not in SEVERITY_PALETTE:
        severity = "UNKNOWN"
    cells = "".join(f"<td>{escape(str(value or ''))}</td>" for value in (
        finding["vulnerability_id"], finding["package"], finding["installed_version"],
        finding["fixed_version"], finding["target"], finding["title"],
    ))
    return f"<tr><td><span class='pill {severity.lower()}'>{escape(severity)}</span></td>{cells}</tr>"


def pdf_styles():
    base = getSampleStyleSheet()
    bold = "DejaVuSans-Bold" if PDF_FONT == "DejaVuSans" else "Helvetica-Bold"
    return {
        "title": ParagraphStyle("ReportTitle", parent=base["Title"], fontName=bold, fontSize=23,
                                leading=28, textColor=colors.HexColor("#0f172a"), alignment=TA_LEFT),
        "subtitle": ParagraphStyle("Subtitle", parent=base["Normal"], fontName=PDF_FONT, fontSize=9,
                                   leading=13, textColor=colors.HexColor("#64748b")),
        "image": ParagraphStyle("ImageTitle", parent=base["Heading2"], fontName=bold, fontSize=17,
                                leading=22, textColor=colors.HexColor("#0f172a"), spaceAfter=3),
        "cell": ParagraphStyle("Cell", parent=base["Normal"], fontName=PDF_FONT, fontSize=6.7,
                               leading=8.5, textColor=colors.HexColor("#263449")),
        "cell_bold": ParagraphStyle("CellBold", parent=base["Normal"], fontName=bold, fontSize=6.7,
                                    leading=8.5, textColor=colors.HexColor("#172033")),
        "header": ParagraphStyle("TableHeader", parent=base["Normal"], fontName=bold, fontSize=6.7,
                                 leading=8.5, textColor=colors.white),
        "metric": ParagraphStyle("Metric", parent=base["Normal"], fontName=bold, fontSize=9,
                                 leading=12, alignment=TA_CENTER),
    }


def render_pdf(payload: dict, logo_png: bytes | None = None) -> bytes:
    report_count = payload.get("report_count", len(payload["reports"]))
    output = io.BytesIO()
    document = SimpleDocTemplate(output, pagesize=landscape(A4), leftMargin=12*mm, rightMargin=12*mm,
                                 topMargin=16*mm, bottomMargin=14*mm, title="Container vulnerability report",
                                 author="LayerScope")
    styles = pdf_styles()
    totals = aggregate_counts(payload)
    story = [Paragraph("Container vulnerability report", styles["title"]),
             Paragraph(f"Generated {escape(format_time(payload['generated_at']))} | {report_count} image report(s)", styles["subtitle"]),
             Spacer(1, 5*mm), severity_table(totals, styles), Spacer(1, 4*mm)]
    if logo_png:
        with PillowImage.open(io.BytesIO(logo_png)) as logo:
            width, height = logo.size
        scale = min((70 * mm) / width, (26 * mm) / height)
        story[0:0] = [ReportImage(io.BytesIO(logo_png), width=width * scale, height=height * scale), Spacer(1, 4*mm)]
    selection = payload.get("selection")
    if selection and selection.get("type") == "groups":
        names = ", ".join(escape(group["name"]) for group in selection["groups"])
        story[2:2] = [Paragraph(f"Groups: {names}", styles["image"]),
                      Paragraph(f"Included {selection['included_scan_count']} of {selection['member_count']} visible members; "
                                f"{selection['unscanned_member_count']} had no completed scan.", styles["subtitle"]),
                      Spacer(1, 4*mm)]
    for index, report in enumerate(payload["reports"]):
        if index:
            story.append(PageBreak())
        story.extend([
            Paragraph(escape(report["image"]), styles["image"]),
            Paragraph(f"Scan #{report['scan_id']} | {report['total']} findings | Completed {escape(format_time(report['finished_at']))}", styles["subtitle"]),
            Spacer(1, 4*mm), severity_table(report["counts"], styles), Spacer(1, 4*mm),
            findings_table(report["findings"], styles),
        ])
    document.build(story, onFirstPage=draw_page, onLaterPages=draw_page)
    return output.getvalue()


def severity_table(counts: dict, styles: dict):
    cells = []
    for severity in SEVERITIES:
        background, foreground, border = SEVERITY_PALETTE[severity]
        cells.append(Paragraph(f"<font color='{foreground}'>{severity}<br/><font size='15'>{counts.get(severity, 0):,}</font></font>", styles["metric"]))
    table = Table([cells], colWidths=[49.5*mm]*5, rowHeights=[18*mm])
    commands = [("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("BOX", (0, 0), (-1, -1), .3, colors.HexColor("#cbd5e1"))]
    for column, severity in enumerate(SEVERITIES):
        background, _, border = SEVERITY_PALETTE[severity]
        commands.extend([("BACKGROUND", (column, 0), (column, 0), colors.HexColor(background)),
                         ("LINEBEFORE", (column, 0), (column, 0), 2.2, colors.HexColor(border))])
    table.setStyle(TableStyle(commands))
    return table


def findings_table(findings: list[dict], styles: dict):
    headers = ["SEVERITY", "VULNERABILITY", "PACKAGE", "INSTALLED", "FIXED VERSION", "TARGET", "TITLE"]
    data = [[Paragraph(header, styles["header"]) for header in headers]]
    for finding in findings:
        values = [finding["severity"], finding["vulnerability_id"], finding["package"],
                  finding["installed_version"], finding["fixed_version"] or "Not listed",
                  finding["target"], finding["title"]]
        data.append([Paragraph(escape(str(value or "")), styles["cell_bold"] if index in (0, 1) else styles["cell"])
                     for index, value in enumerate(values)])
    if not findings:
        data.append([Paragraph("No vulnerabilities were recorded.", styles["cell"])] + [""]*6)
    table = Table(data, repeatRows=1, colWidths=[22*mm, 31*mm, 34*mm, 26*mm, 29*mm, 40*mm, 65.5*mm], splitByRow=True)
    commands = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, -1), PDF_FONT),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), .25, colors.HexColor("#dbe3ee")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]
    for row_index, finding in enumerate(findings, start=1):
        severity = finding["severity"] if finding["severity"] in SEVERITY_PALETTE else "UNKNOWN"
        background, foreground, border = SEVERITY_PALETTE[severity]
        commands.extend([("BACKGROUND", (0, row_index), (0, row_index), colors.HexColor(background)),
                         ("TEXTCOLOR", (0, row_index), (0, row_index), colors.HexColor(foreground)),
                         ("LINEBEFORE", (0, row_index), (0, row_index), 2, colors.HexColor(border))])
    table.setStyle(TableStyle(commands))
    return table


def draw_page(canvas, document):
    canvas.saveState()
    width, height = landscape(A4)
    canvas.setFillColor(colors.HexColor("#0f172a"))
    canvas.rect(0, height-8*mm, width, 8*mm, fill=1, stroke=0)
    canvas.setFont(PDF_FONT, 7)
    canvas.setFillColor(colors.HexColor("#64748b"))
    canvas.drawString(12*mm, 7*mm, "LayerScope - Container vulnerability report")
    canvas.drawRightString(width-12*mm, 7*mm, f"Page {document.page}")
    canvas.restoreState()
