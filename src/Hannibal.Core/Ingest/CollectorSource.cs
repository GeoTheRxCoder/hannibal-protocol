using Hannibal.Contracts;

namespace Hannibal.Core.Ingest;

/// <summary>
/// A sensor adapter (ETW session, event-log reader, ...). The host registers
/// it with the trusted ingestor, hands it a signer bound to its channel, and
/// polls its lost-event counter for telemetry health.
/// </summary>
public interface ICollectorSource : IDisposable
{
    string CollectorId { get; }
    string CaptureChannel { get; }
    void Start(ObservationSigner signer, Action<RawObservation> emit);
    /// <summary>Events the sensor dropped since the previous call (for example ETW EventsLost).</summary>
    long TakeLostEvents();
}
