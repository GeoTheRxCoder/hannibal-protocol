using Hannibal.Contracts;

namespace Hannibal.Core.Maneuver;

public sealed record LadderState(IsolationRung Rung, long EnteredMs, long ExpiresMs);
public sealed record LadderMove(LadderState State, bool Changed, string Reason);

/// <summary>
/// "The Maneuver" (Cannae motif): instead of one hard stop, the response
/// yields and then closes around a subject one bounded rung at a time.
///
///   Observe -> Watch -> EnvelopEgress -> Hold
///
/// Rules: a behavioral decision climbs at most ONE rung per evaluation; every
/// rung has a TTL and steps DOWN one rung when it expires without renewed
/// support; only an exact signed-indicator match (a verified fact, not a
/// behavioral hypothesis) may enter Hold directly. In the beta every rung
/// above Watch is simulated.
/// </summary>
public static class IsolationLadder
{
    public const long WatchTtlMs = 900_000, EnvelopTtlMs = 900_000, HoldReviewMs = 7L * 24 * 3600 * 1000;

    public static LadderMove Next(LadderState? current, DecisionKind decision, long nowMs)
    {
        var cur = current ?? new LadderState(IsolationRung.Observe, nowMs, nowMs);

        if (cur.Rung != IsolationRung.Observe && nowMs >= cur.ExpiresMs)
        {
            var down = cur.Rung - 1;
            cur = new LadderState(down, nowMs, nowMs + (down == IsolationRung.Observe ? 0 : WatchTtlMs));
            if (!Supports(decision, down + 1)) return new(cur, true, "TTL_EXPIRED_STEP_DOWN");
        }

        IsolationRung ceiling = decision switch
        {
            DecisionKind.Quarantine => IsolationRung.Hold,
            DecisionKind.TemporaryNetworkBlock => IsolationRung.EnvelopEgress,
            DecisionKind.Alert => IsolationRung.Watch,
            _ => IsolationRung.Observe
        };
        if (ceiling <= cur.Rung)
        {
            // Renewed support at the current rung refreshes its TTL; it never extends past the cap.
            if (ceiling == cur.Rung && cur.Rung != IsolationRung.Observe)
                return new(cur with { ExpiresMs = nowMs + Ttl(cur.Rung) }, false, "RUNG_RENEWED");
            return new(cur, current is null || cur != current, "NO_CLIMB");
        }
        var target = decision == DecisionKind.Quarantine ? IsolationRung.Hold : cur.Rung + 1;
        return new(new LadderState(target, nowMs, nowMs + Ttl(target)), true,
            target == ceiling ? "CLIMBED_TO_DECISION_RUNG" : "CLIMBED_ONE_RUNG");
    }

    private static bool Supports(DecisionKind d, IsolationRung rung) => rung switch
    {
        IsolationRung.Hold => d == DecisionKind.Quarantine,
        IsolationRung.EnvelopEgress => d is DecisionKind.TemporaryNetworkBlock or DecisionKind.Quarantine,
        IsolationRung.Watch => d is DecisionKind.Alert or DecisionKind.TemporaryNetworkBlock or DecisionKind.Quarantine,
        _ => true
    };

    private static long Ttl(IsolationRung r) => r switch
    {
        IsolationRung.Watch => WatchTtlMs,
        IsolationRung.EnvelopEgress => EnvelopTtlMs,
        IsolationRung.Hold => HoldReviewMs,
        _ => 0
    };
}
