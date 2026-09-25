from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.groups import group_overview_payload, group_payload
from app.models import Finding, ImageArchive, ImageGroup, ImageGroupMember, Scan


def test_group_summary_uses_latest_completed_scan_and_visible_members():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    group = ImageGroup(name="Payments", description="Related services", color="rose")
    visible = ImageArchive(path="/images/api.tar", name="api.tar", size=10,
                           modified_at=datetime.now(timezone.utc))
    hidden = ImageArchive(path="/images/old.tar", name="old.tar", size=10,
                          modified_at=datetime.now(timezone.utc), hidden=True)
    db.add_all([group, visible, hidden]); db.flush()
    db.add_all([ImageGroupMember(group_id=group.id, image_id=visible.id),
                ImageGroupMember(group_id=group.id, image_id=hidden.id)])
    old = Scan(image_id=visible.id, status="completed")
    latest = Scan(image_id=visible.id, status="completed")
    db.add_all([old, latest]); db.flush()
    db.add(Finding(scan_id=old.id, target="os", vulnerability_id="CVE-OLD", package_name="old",
                   installed_version="1", fixed_version="2", severity="LOW", title="", description="", primary_url=""))
    db.add(Finding(scan_id=latest.id, target="os", vulnerability_id="CVE-NEW", package_name="new",
                   installed_version="1", fixed_version="2", severity="CRITICAL", title="", description="", primary_url=""))
    db.commit()

    result = group_payload(db, group, include_members=True)

    assert result["member_count"] == 1
    assert result["scanned_count"] == 1
    assert result["unscanned_count"] == 0
    assert result["scan_status"] == "scanned"
    assert result["highest_severity"] == "CRITICAL"
    assert result["severity"] == {"CRITICAL": 1}
    assert result["total_findings"] == 1
    assert [member["name"] for member in result["members"]] == ["api.tar"]


def test_group_overview_counts_memberships_and_overlaps_explicitly():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    primary = ImageGroup(name="Primary", description="", color="blue")
    shared = ImageGroup(name="Shared", description="", color="violet")
    empty = ImageGroup(name="Empty", description="", color="slate")
    scanned = ImageArchive(path="/images/scanned.tar", name="scanned.tar", size=10,
                           modified_at=datetime.now(timezone.utc))
    unscanned = ImageArchive(path="/images/unscanned.tar", name="unscanned.tar", size=10,
                             modified_at=datetime.now(timezone.utc))
    hidden = ImageArchive(path="/images/hidden.tar", name="hidden.tar", size=10,
                          modified_at=datetime.now(timezone.utc), hidden=True)
    db.add_all([primary, shared, empty, scanned, unscanned, hidden]); db.flush()
    db.add_all([
        ImageGroupMember(group_id=primary.id, image_id=scanned.id),
        ImageGroupMember(group_id=primary.id, image_id=unscanned.id),
        ImageGroupMember(group_id=shared.id, image_id=scanned.id),
        ImageGroupMember(group_id=shared.id, image_id=hidden.id),
    ])
    scan = Scan(image_id=scanned.id, status="completed")
    db.add(scan); db.flush()
    db.add(Finding(scan_id=scan.id, target="os", vulnerability_id="CVE-SHARED", package_name="shared",
                   installed_version="1", fixed_version="2", severity="HIGH", title="",
                   description="", primary_url=""))
    db.commit()

    result = group_overview_payload(db)
    by_name = {group["name"]: group for group in result["groups"]}

    assert result["group_count"] == 3
    assert result["membership_count"] == 3
    assert result["scanned_membership_count"] == 2
    assert result["unscanned_membership_count"] == 1
    assert result["severity"] == {"HIGH": 2}
    assert result["total_findings"] == 2
    assert result["statuses"] == {"partial": 1, "scanned": 1, "empty": 1}
    assert by_name["Primary"]["scan_status"] == "partial"
    assert by_name["Primary"]["highest_severity"] == "HIGH"
    assert by_name["Shared"]["member_count"] == 1
    assert by_name["Empty"]["scan_status"] == "empty"
