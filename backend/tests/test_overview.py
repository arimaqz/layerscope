from datetime import datetime, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.database import Base
import pytest
from fastapi import HTTPException
from app.main import overview, scan_summary
from app.models import Finding, ImageArchive, Scan


def test_overview_with_completed_findings():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    image = ImageArchive(path="/images/example.tar", name="example.tar", size=10,
                         modified_at=datetime.now(timezone.utc))
    session.add(image); session.flush()
    scan = Scan(image_id=image.id, status="completed")
    session.add(scan); session.flush()
    session.add(Finding(scan_id=scan.id, target="alpine", vulnerability_id="CVE-TEST",
                        package_name="openssl", installed_version="1", fixed_version="2",
                        severity="CRITICAL", title="Test", description="", primary_url=""))
    session.commit()

    result = overview(session)

    assert result["total_findings"] == 1
    assert result["severity"] == {"CRITICAL": 1}
    assert result["most_vulnerable"] == [{"image_id": image.id, "name": "example.tar", "total": 1}]
    assert result["risk_packages"][0]["name"] == "openssl"


def test_scan_summary_is_compact_and_counts_severities():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    image = ImageArchive(path="/images/example.tar", name="example.tar", size=10,
                         modified_at=datetime.now(timezone.utc))
    session.add(image); session.flush()
    scan = Scan(image_id=image.id, status="completed", progress=100, stage="complete")
    session.add(scan); session.flush()
    session.add_all([
        Finding(scan_id=scan.id, target="alpine", vulnerability_id="CVE-ONE",
                package_name="one", installed_version="1", fixed_version="2",
                severity="HIGH", title="One", description="", primary_url=""),
        Finding(scan_id=scan.id, target="alpine", vulnerability_id="CVE-TWO",
                package_name="two", installed_version="1", fixed_version="2",
                severity="LOW", title="Two", description="", primary_url=""),
    ])
    session.commit()

    result = scan_summary(scan.id, session)

    assert result["image_id"] == image.id
    assert result["status"] == "completed"
    assert result["counts"] == {"HIGH": 1, "LOW": 1}
    assert result["total"] == 2

    with pytest.raises(HTTPException) as missing:
        scan_summary(999, session)
    assert missing.value.status_code == 404
