import sqlite3
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
def test_provenance_schema_and_foreign_keys():
    db=sqlite3.connect(":memory:")
    db.executescript((ROOT/"db/001_initial.sql").read_text())
    db.executescript((ROOT/"db/002_evidence_provenance.sql").read_text())
    assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    assert db.execute("PRAGMA foreign_key_check").fetchall()==[]
    assert {x[0] for x in db.execute("SELECT version FROM schema_migrations")} == {1,2}
    # An evidence row cannot refer to a missing incident.
    try:
        db.execute("""INSERT INTO evidence_records
          (evidence_id,incident_id,device_id,subject_key,
           evidence_family,capture_channel,producer_id,observed_ms,trust_status,confidence)
          VALUES('e1','missing','host-1','p','Behavior','etw','producer',100,
                 'verified',0.95)""")
    except sqlite3.IntegrityError:
        pass
    else:
        assert False, "FK should reject evidence without incident"
