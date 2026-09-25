from datetime import datetime, timezone

from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.groups import group_overview_payload, group_payloads
from app.main import image_payloads, overview
from app.models import Finding, ImageArchive, ImageGroup, ImageGroupMember, Scan
from app.reports import group_export_selection


def seeded_database(size=30):
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine, expire_on_commit=False)()
    group = ImageGroup(name="Bulk", description="Query scaling fixture", color="blue")
    db.add(group); db.flush()
    for index in range(size):
        image = ImageArchive(path=f"/images/{index}.tar", name=f"{index}.tar", size=index + 1,
                             modified_at=datetime.now(timezone.utc))
        db.add(image); db.flush()
        db.add(ImageGroupMember(group_id=group.id, image_id=image.id))
        scan = Scan(image_id=image.id, status="completed", progress=100)
        db.add(scan); db.flush()
        db.add(Finding(scan_id=scan.id, target="os", vulnerability_id=f"CVE-{index}",
                       package_name="openssl", installed_version="1", fixed_version="2",
                       severity="HIGH", title="", description="", primary_url=""))
    db.commit()
    return engine, db, group


def query_count(engine, operation):
    counter = [0]
    def before_cursor(*_args):
        counter[0] += 1
    event.listen(engine, "before_cursor_execute", before_cursor)
    try:
        operation()
    finally:
        event.remove(engine, "before_cursor_execute", before_cursor)
    return counter[0]


def test_image_payload_queries_do_not_grow_per_image():
    engine, db, _group = seeded_database()
    rows = list(db.scalars(select(ImageArchive).order_by(ImageArchive.name)).all())
    count = query_count(engine, lambda: image_payloads(db, rows))
    assert count <= 3


def test_group_and_overview_queries_are_set_based():
    engine, db, group = seeded_database()
    group_count = query_count(engine, lambda: group_payloads(db, [group]))
    overview_count = query_count(engine, lambda: overview(db))
    assert group_count <= 3
    assert overview_count <= 6


def test_group_analytics_queries_do_not_grow_per_member():
    small_engine, small_db, _small_group = seeded_database(size=2)
    large_engine, large_db, _large_group = seeded_database(size=80)

    small_count = query_count(small_engine, lambda: group_overview_payload(small_db))
    large_count = query_count(large_engine, lambda: group_overview_payload(large_db))

    assert small_count <= 4
    assert large_count == small_count


def test_group_export_selection_queries_do_not_grow_per_member():
    small_engine, small_db, small_group = seeded_database(size=2)
    large_engine, large_db, large_group = seeded_database(size=80)

    small_count = query_count(small_engine, lambda: group_export_selection(small_db, [small_group.id]))
    large_count = query_count(large_engine, lambda: group_export_selection(large_db, [large_group.id]))

    assert small_count <= 5
    assert large_count == small_count
