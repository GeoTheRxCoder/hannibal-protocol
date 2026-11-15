import pathlib
import sqlite3
import pytest

SCHEMA = pathlib.Path(__file__).resolve().parents[2] / "db" / "001_initial.sql"

def test_schema_integrity_and_uniqueness():
    connection=sqlite3.connect(":memory:")
    connection.executescript(SCHEMA.read_text())
    assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    event=("ev-1", 1, "device-1", "Sentry", "ProcessObserved", 100, 101, "{}")
    connection.execute("""INSERT INTO security_events
      (event_id,schema_version,device_id,source_agent,event_type,
       observed_ms,ingested_ms,payload_json) VALUES(?,?,?,?,?,?,?,?)""", event)
    with pytest.raises(sqlite3.IntegrityError):
        connection.execute("""INSERT INTO security_events
          (event_id,schema_version,device_id,source_agent,event_type,
           observed_ms,ingested_ms,payload_json) VALUES(?,?,?,?,?,?,?,?)""",event)
    node=("node-1","device-1","Process","boot:pid:start",100,100,"{}")
    connection.execute("""INSERT INTO graph_nodes
      (node_id,device_id,node_type,identity_key,first_seen_ms,last_seen_ms,properties_json)
      VALUES (?,?,?,?,?,?,?)""",node)
    with pytest.raises(sqlite3.IntegrityError):
        connection.execute("""INSERT INTO graph_edges
         (edge_id,source_node_id,target_node_id,relation_type,
          first_seen_ms,last_seen_ms,confidence)
         VALUES('edge-1','node-1','nonexistent','SPAWNED',100,100,.9)""")
    assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
    connection.close()
