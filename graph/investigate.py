"""Evidence-bound, time-respecting directed graph paths.

For incident explanation only. A path is a HYPOTHESIS and never counts as
independent evidence of malware, nor authorizes containment.
"""
from __future__ import annotations
from dataclasses import dataclass
from collections import defaultdict, deque

LEGAL_RELATIONS = {
    ("Process", "SPAWNED", "Process"),
    ("Process", "EXECUTED", "FileOccurrence"),
    ("FileOccurrence", "INSTANCE_OF", "FileArtifact"),
    ("Process", "CONNECTED_TO", "NetworkEndpoint"),
    ("Account", "OWNS", "Process"),
    ("Process", "PERSISTED_AS", "PersistenceEntry"),
}

@dataclass(frozen=True)
class EdgeObservation:
    src: str
    src_type: str
    dst: str
    dst_type: str
    relation: str
    device_id: str
    observed_ms: int
    confidence: float
    evidence_id: str
    raw_root_ids: tuple[str, ...]

def investigate(seed: str, device_id: str, observations: list[EdgeObservation],
                start_ms: int, end_ms: int, max_hops: int = 3,
                max_edges: int = 500, max_gap_ms: int = 900_000
                ) -> list[tuple[EdgeObservation, ...]]:
    """Return audit-friendly ordered paths; never extrapolate causality."""
    if not (0 < max_hops <= 5 and 0 < max_edges <= 2000 and
            0 <= start_ms <= end_ms and max_gap_ms >= 0):
        raise ValueError("Invalid bounded traversal parameters")
    by_source = defaultdict(list)
    for e in observations:
        if not (e.device_id == device_id and
                (e.src_type, e.relation, e.dst_type) in LEGAL_RELATIONS and
                start_ms <= e.observed_ms <= end_ms and
                0 <= e.confidence <= 1 and
                e.evidence_id and e.raw_root_ids and
                all(x for x in e.raw_root_ids)):
            continue
        by_source[e.src].append(e)
    for seq in by_source.values():
        seq.sort(key=lambda e: (e.observed_ms, e.dst, e.evidence_id))

    paths = []
    frontier = deque([(seed, tuple(), frozenset([seed]))])
    traversed = 0
    while frontier and traversed < max_edges:
        src, path, seen = frontier.popleft()
        if len(path) >= max_hops:
            continue
        for edge in by_source.get(src, []):
            if traversed >= max_edges:
                break
            traversed += 1
            if edge.dst in seen:
                continue
            if path:
                if edge.observed_ms < path[-1].observed_ms:
                    continue
                if edge.observed_ms - path[-1].observed_ms > max_gap_ms:
                    continue
            new_path = (*path, edge)
            paths.append(new_path)
            frontier.append((edge.dst, new_path, seen | {edge.dst}))
    return paths
