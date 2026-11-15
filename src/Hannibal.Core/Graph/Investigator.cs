using Hannibal.Core.Storage;

namespace Hannibal.Core.Graph;

/// <summary>
/// Evidence-bound, time-respecting bounded BFS (C# port of graph/investigate.py).
/// A returned path is a HYPOTHESIS for explanation. It is never proof of
/// intent and never independent corroboration of the observations it is made of.
/// </summary>
public static class Investigator
{
    public static readonly IReadOnlySet<(string, string, string)> LegalRelations = new HashSet<(string, string, string)>
    {
        ("Process", "SPAWNED", "Process"),
        ("Process", "EXECUTED", "FileOccurrence"),
        ("FileOccurrence", "INSTANCE_OF", "FileArtifact"),
        ("Process", "CONNECTED_TO", "NetworkEndpoint"),
        ("Account", "OWNS", "Process"),
        ("Process", "PERSISTED_AS", "PersistenceEntry"),
    };

    public static bool IsLegal(string srcType, string relation, string dstType) =>
        LegalRelations.Contains((srcType, relation, dstType));

    public static List<IReadOnlyList<EdgeObservationRow>> Investigate(
        string seed, string deviceId, IEnumerable<EdgeObservationRow> observations,
        long startMs, long endMs, int maxHops = 3, int maxEdges = 500,
        long maxGapMs = 900_000, int maxFanout = 64)
    {
        if (maxHops is <= 0 or > 5 || maxEdges is <= 0 or > 2000 || startMs < 0 || startMs > endMs || maxGapMs < 0)
            throw new ArgumentException("Invalid bounded traversal parameters");

        var bySource = new Dictionary<string, List<EdgeObservationRow>>(StringComparer.Ordinal);
        foreach (var e in observations)
        {
            if (e.DeviceId != deviceId || !IsLegal(e.SrcType, e.Relation, e.DstType)) continue;
            if (e.ObservedMs < startMs || e.ObservedMs > endMs) continue;
            if (!(e.Confidence >= 0 && e.Confidence <= 1) || string.IsNullOrEmpty(e.RootEventId)) continue;
            if (!bySource.TryGetValue(e.Src, out var l)) bySource[e.Src] = l = [];
            l.Add(e);
        }
        foreach (var l in bySource.Values)
            l.Sort((a, b) => a.ObservedMs != b.ObservedMs ? a.ObservedMs.CompareTo(b.ObservedMs)
                : string.CompareOrdinal(a.Dst, b.Dst));

        var paths = new List<IReadOnlyList<EdgeObservationRow>>();
        var frontier = new Queue<(string Node, EdgeObservationRow[] Path, HashSet<string> Seen)>();
        frontier.Enqueue((seed, [], [seed]));
        int traversed = 0;
        while (frontier.Count > 0 && traversed < maxEdges)
        {
            var (src, path, seen) = frontier.Dequeue();
            if (path.Length >= maxHops || !bySource.TryGetValue(src, out var edges)) continue;
            // Dependency-explosion control: a hub (svchost, explorer) is reported, not expanded.
            if (path.Length > 0 && edges.Count > maxFanout) continue;
            foreach (var edge in edges)
            {
                if (traversed >= maxEdges) break;
                traversed++;
                if (seen.Contains(edge.Dst)) continue;
                if (path.Length > 0)
                {
                    long last = path[^1].ObservedMs;
                    if (edge.ObservedMs < last || edge.ObservedMs - last > maxGapMs) continue;
                }
                EdgeObservationRow[] next = [.. path, edge];
                paths.Add(next);
                frontier.Enqueue((edge.Dst, next, [.. seen, edge.Dst]));
            }
        }
        return paths;
    }
}
