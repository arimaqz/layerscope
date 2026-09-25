from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import delete, desc, func, select
from sqlalchemy.orm import Session

from .auth import audit, require_roles
from .config import settings
from .database import get_db
from .models import Finding, ImageArchive, ImageGroup, ImageGroupMember, Scan


def image_source(path: str) -> str:
    resolved = Path(path).resolve()
    return "upload" if settings.upload_dir.resolve() in resolved.parents else "mounted"


router = APIRouter(prefix="/api/groups", tags=["groups"])
COLORS = {"blue", "emerald", "amber", "rose", "violet", "slate"}
SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")


class GroupCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=100)
    description: str = Field(default="", max_length=500)
    color: str = "blue"


class GroupUpdate(GroupCreate):
    pass


class GroupMembers(BaseModel):
    model_config = ConfigDict(extra="forbid")
    image_ids: list[int] = Field(default_factory=list, max_length=5000)


def clean_group(name: str, description: str, color: str):
    clean_name = name.strip()
    if not clean_name:
        raise HTTPException(400, "Group name cannot be blank")
    clean_color = color.strip().casefold()
    if clean_color not in COLORS:
        raise HTTPException(400, "Unsupported group color")
    return clean_name, description.strip(), clean_color


def ensure_unique_name(db: Session, name: str, excluding_id: int | None = None):
    query = select(ImageGroup.id).where(func.lower(ImageGroup.name) == name.casefold())
    if excluding_id is not None:
        query = query.where(ImageGroup.id != excluding_id)
    if db.scalar(query):
        raise HTTPException(409, "A group with that name already exists")


def latest_completed_scan(db: Session, image_id: int):
    return db.scalar(select(Scan).where(Scan.image_id == image_id, Scan.status == "completed")
                     .order_by(desc(Scan.id)).limit(1))


def finding_counts(db: Session, scan_id: int | None):
    if not scan_id:
        return {}
    return dict(db.execute(select(Finding.severity, func.count()).where(Finding.scan_id == scan_id)
                           .group_by(Finding.severity)).all())


def group_payloads(db: Session, groups: list[ImageGroup], include_members: bool = False):
    """Build all group summaries using a constant number of set-based queries."""
    group_ids = [group.id for group in groups]
    memberships: dict[int, list[ImageArchive]] = {group_id: [] for group_id in group_ids}
    if group_ids:
        rows = db.execute(
            select(ImageGroupMember.group_id, ImageArchive)
            .join(ImageArchive, ImageArchive.id == ImageGroupMember.image_id)
            .where(ImageGroupMember.group_id.in_(group_ids), ImageArchive.hidden.is_(False))
            .order_by(ImageArchive.name)).all()
        for group_id, image in rows:
            memberships[group_id].append(image)

    image_ids = sorted({image.id for images in memberships.values() for image in images})
    latest_completed_by_image: dict[int, Scan] = {}
    latest_by_image: dict[int, Scan] = {}
    if image_ids:
        completed_ids = (select(Scan.image_id, func.max(Scan.id).label("scan_id"))
                         .where(Scan.image_id.in_(image_ids), Scan.status == "completed")
                         .group_by(Scan.image_id).subquery())
        completed = db.scalars(select(Scan).join(completed_ids, Scan.id == completed_ids.c.scan_id)).all()
        latest_completed_by_image = {scan.image_id: scan for scan in completed}
        if include_members:
            latest_ids = (select(Scan.image_id, func.max(Scan.id).label("scan_id"))
                          .where(Scan.image_id.in_(image_ids)).group_by(Scan.image_id).subquery())
            latest = db.scalars(select(Scan).join(latest_ids, Scan.id == latest_ids.c.scan_id)).all()
            latest_by_image = {scan.image_id: scan for scan in latest}

    counts_by_scan: dict[int, dict[str, int]] = {}
    completed_scan_ids = [scan.id for scan in latest_completed_by_image.values()]
    if completed_scan_ids:
        for scan_id, level, count in db.execute(
                select(Finding.scan_id, Finding.severity, func.count())
                .where(Finding.scan_id.in_(completed_scan_ids))
                .group_by(Finding.scan_id, Finding.severity)).all():
            counts_by_scan.setdefault(scan_id, {})[level] = count

    payloads = []
    for group in groups:
        severity: dict[str, int] = {}
        members = []
        group_images = memberships.get(group.id, [])
        scanned_count = 0
        for image in group_images:
            completed = latest_completed_by_image.get(image.id)
            counts = counts_by_scan.get(completed.id, {}) if completed else {}
            if completed:
                scanned_count += 1
            for level, count in counts.items():
                severity[level] = severity.get(level, 0) + count
            if include_members:
                latest = latest_by_image.get(image.id)
                members.append({
                    "id": image.id, "name": image.name, "source": image_source(image.path), "size": image.size,
                    "latest_status": latest.status if latest else None,
                    "latest_scan_id": latest.id if latest else None,
                    "counts": counts, "total": sum(counts.values()),
                })
        member_count = len(group_images)
        unscanned_count = member_count - scanned_count
        if not member_count:
            scan_status = "empty"
        elif not scanned_count:
            scan_status = "unscanned"
        elif unscanned_count:
            scan_status = "partial"
        else:
            scan_status = "scanned"
        highest_severity = next((level for level in SEVERITY_ORDER if severity.get(level, 0) > 0), None)
        result = {
            "id": group.id, "name": group.name, "description": group.description, "color": group.color,
            "member_count": member_count, "scanned_count": scanned_count, "unscanned_count": unscanned_count,
            "scan_status": scan_status, "highest_severity": highest_severity, "severity": severity,
            "total_findings": sum(severity.values()), "created_at": group.created_at,
            "updated_at": group.updated_at,
        }
        if include_members:
            result["members"] = members
        payloads.append(result)
    return payloads


def group_payload(db: Session, group: ImageGroup, include_members: bool = False):
    return group_payloads(db, [group], include_members)[0]


def group_overview_payload(db: Session):
    """Return all group summaries plus membership-weighted analytics in bounded queries.

    A visible image contributes once within each group. If it belongs to several groups,
    its latest completed scan contributes once to every one of those group summaries.
    """
    groups = list(db.scalars(select(ImageGroup).order_by(ImageGroup.name)).all())
    summaries = group_payloads(db, groups)
    severity: dict[str, int] = {}
    statuses: dict[str, int] = {}
    for group in summaries:
        for level, count in group["severity"].items():
            severity[level] = severity.get(level, 0) + count
        status = group["scan_status"]
        statuses[status] = statuses.get(status, 0) + 1
    membership_count = sum(group["member_count"] for group in summaries)
    scanned_membership_count = sum(group["scanned_count"] for group in summaries)
    return {
        "group_count": len(summaries),
        "membership_count": membership_count,
        "scanned_membership_count": scanned_membership_count,
        "unscanned_membership_count": membership_count - scanned_membership_count,
        "severity": severity,
        "total_findings": sum(severity.values()),
        "statuses": statuses,
        "groups": summaries,
    }


@router.get("")
def list_groups(db: Session = Depends(get_db)):
    groups = list(db.scalars(select(ImageGroup).order_by(ImageGroup.name)).all())
    return group_payloads(db, groups)


@router.get("/overview")
def group_overview(db: Session = Depends(get_db)):
    return group_overview_payload(db)


@router.get("/{group_id}")
def get_group(group_id: int, db: Session = Depends(get_db)):
    group = db.get(ImageGroup, group_id)
    if not group:
        raise HTTPException(404, "Group not found")
    return group_payload(db, group, include_members=True)


@router.post("", status_code=201)
def create_group(body: GroupCreate, request: Request, db: Session = Depends(get_db),
                 actor=Depends(require_roles("operator", "admin"))):
    name, description, color = clean_group(body.name, body.description, body.color)
    ensure_unique_name(db, name)
    group = ImageGroup(name=name, description=description, color=color)
    db.add(group); db.flush()
    audit(db, "group_create", "success", request, actor.id, {"group_id": group.id, "name": name})
    db.commit()
    return group_payload(db, group)


@router.post("/{group_id}/update")
def update_group(group_id: int, body: GroupUpdate, request: Request, db: Session = Depends(get_db),
                 actor=Depends(require_roles("operator", "admin"))):
    group = db.get(ImageGroup, group_id)
    if not group:
        raise HTTPException(404, "Group not found")
    name, description, color = clean_group(body.name, body.description, body.color)
    ensure_unique_name(db, name, group.id)
    group.name = name; group.description = description; group.color = color
    audit(db, "group_update", "success", request, actor.id, {"group_id": group.id, "name": name})
    db.commit()
    return group_payload(db, group)


@router.post("/{group_id}/members")
def replace_members(group_id: int, body: GroupMembers, request: Request, db: Session = Depends(get_db),
                    actor=Depends(require_roles("operator", "admin"))):
    group = db.get(ImageGroup, group_id)
    if not group:
        raise HTTPException(404, "Group not found")
    image_ids = list(dict.fromkeys(body.image_ids))
    if image_ids:
        valid_ids = set(db.scalars(select(ImageArchive.id).where(
            ImageArchive.id.in_(image_ids), ImageArchive.hidden.is_(False))).all())
        missing = sorted(set(image_ids) - valid_ids)
        if missing:
            raise HTTPException(400, f"Unavailable image IDs: {', '.join(map(str, missing[:10]))}")
    db.execute(delete(ImageGroupMember).where(ImageGroupMember.group_id == group.id))
    db.add_all(ImageGroupMember(group_id=group.id, image_id=image_id) for image_id in image_ids)
    audit(db, "group_members_replace", "success", request, actor.id,
          {"group_id": group.id, "member_count": len(image_ids)})
    db.commit()
    return group_payload(db, group, include_members=True)


@router.post("/{group_id}/members/add")
def add_members(group_id: int, body: GroupMembers, request: Request, db: Session = Depends(get_db),
                actor=Depends(require_roles("operator", "admin"))):
    group = db.get(ImageGroup, group_id)
    if not group:
        raise HTTPException(404, "Group not found")
    image_ids = list(dict.fromkeys(body.image_ids))
    if not image_ids:
        raise HTTPException(400, "Select at least one image")
    valid_ids = set(db.scalars(select(ImageArchive.id).where(
        ImageArchive.id.in_(image_ids), ImageArchive.hidden.is_(False))).all())
    missing = sorted(set(image_ids) - valid_ids)
    if missing:
        raise HTTPException(400, f"Unavailable image IDs: {', '.join(map(str, missing[:10]))}")
    existing = set(db.scalars(select(ImageGroupMember.image_id).where(
        ImageGroupMember.group_id == group.id, ImageGroupMember.image_id.in_(image_ids))).all())
    additions = [image_id for image_id in image_ids if image_id not in existing]
    db.add_all(ImageGroupMember(group_id=group.id, image_id=image_id) for image_id in additions)
    audit(db, "group_members_add", "success", request, actor.id,
          {"group_id": group.id, "requested_count": len(image_ids), "added_count": len(additions)})
    db.commit()
    return {"group": group_payload(db, group, include_members=True), "added_image_ids": additions,
            "already_member_image_ids": sorted(existing)}


@router.delete("/{group_id}")
def delete_group(group_id: int, request: Request, db: Session = Depends(get_db),
                 actor=Depends(require_roles("operator", "admin"))):
    group = db.get(ImageGroup, group_id)
    if not group:
        raise HTTPException(404, "Group not found")
    name = group.name
    db.execute(delete(ImageGroupMember).where(ImageGroupMember.group_id == group.id))
    db.execute(delete(ImageGroup).where(ImageGroup.id == group.id))
    audit(db, "group_delete", "success", request, actor.id, {"group_id": group_id, "name": name})
    db.commit()
    return {"group_id": group_id, "deleted": True, "images_deleted": False}
