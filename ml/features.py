"""Hannibal feature schema v2: raw facts, no detector outputs or policy feedback.

Observation is a 60-second window for a root process lineage.
Missing source data must be marked unavailable, not silently zero-filled.
"""
FEATURE_SCHEMA = "lineage-60s-v2"
FEATURES = [
    "process_starts",
    "unique_remote_destinations",
    "outbound_connection_attempts",
    "unsigned_executable_starts",
    "persistence_changes",
    "os_denied_connection_attempts",
    "max_process_lineage_depth",
    "new_executable_hashes_30d",
]
