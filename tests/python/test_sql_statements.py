"""Prepares every SQL constant in src/Hannibal.Core/Storage/Sql.cs against the
migrated schema, so a typo in C# SQL fails CI even where .NET is unavailable."""
import pathlib, re, sqlite3
import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]

def statements():
    src = (ROOT / "src/Hannibal.Core/Storage/Sql.cs").read_text()
    out = []
    for name, body in re.findall(r'public const string (\w+) = "((?:[^"\\]|\\.)*)";', src):
        out.append((name, body.replace('\\"', '"')))
    return out

@pytest.fixture(scope="module")
def db():
    c = sqlite3.connect(":memory:")
    for f in ("001_initial.sql", "002_evidence_provenance.sql", "003_beta_runtime.sql"):
        c.executescript((ROOT / "db" / f).read_text())
    return c

def test_catalogue_is_complete():
    assert len(statements()) >= 50

@pytest.mark.parametrize("name,sql", statements())
def test_statement_prepares(db, name, sql):
    db.execute("EXPLAIN " + sql, [None] * sql.count("?"))

def test_broker_schema_applies():
    c = sqlite3.connect(":memory:")
    c.executescript((ROOT / "db/broker_001.sql").read_text())
    c.execute("INSERT INTO broker_intents(action_id,idempotency_key,decision_id,command,device_id,target_key,state,simulated,created_ms,updated_ms,detail_json) "
              "VALUES('a','k','d','SimulateNetworkBlock','h','t','INTENDED',1,1,1,'{}')")
    with pytest.raises(sqlite3.IntegrityError):  # the broker table cannot even record a non-simulated action
        c.execute("INSERT INTO broker_intents(action_id,idempotency_key,decision_id,command,device_id,target_key,state,simulated,created_ms,updated_ms,detail_json) "
                  "VALUES('b','k2','d','SimulateNetworkBlock','h','t','INTENDED',0,1,1,'{}')")
    with pytest.raises(sqlite3.IntegrityError):
        c.execute("INSERT INTO broker_intents(action_id,idempotency_key,decision_id,command,device_id,target_key,state,simulated,created_ms,updated_ms,detail_json) "
                  "VALUES('c','k3','d','TerminateProcess','h','t','INTENDED',1,1,1,'{}')")

def test_beta_runtime_constraints(db):
    with pytest.raises(sqlite3.IntegrityError):
        db.execute("INSERT INTO isolation_ladder VALUES('h','s',4,1,2,NULL,1)")
    with pytest.raises(sqlite3.IntegrityError):
        db.execute("INSERT INTO canary_manifest VALUES('c','h','executable','x',NULL,NULL,10,'deployed',1)")
