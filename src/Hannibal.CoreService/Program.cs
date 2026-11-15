// Hannibal Core service host. Thin shell: all behaviour lives in the tested
// Hannibal.Core runtime and Hannibal.Windows.CoreHost.
// Run as a console app with:  HannibalCoreService.exe --console
using Hannibal.Core.Storage;
using Hannibal.Windows;
using Hannibal.Windows.Etw;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(o => o.ServiceName = "HannibalCore");
builder.Services.AddHostedService<CoreWorker>();
builder.Build().Run();

sealed class CoreWorker(ILogger<CoreWorker> log, IConfiguration config) : BackgroundService
{
    protected override Task ExecuteAsync(CancellationToken ct)
    {
        var paths = HostPaths.Default;
        bool etw = config.GetValue("Hannibal:EnableEtwCollectors", true);
        IReadOnlySet<string> DecoyPaths()
        {
            try
            {
                using var db = SqliteDb.Open(Path.Combine(paths.Core, "core.db"), readOnly: true);
                return db.Query("SELECT location FROM canary_manifest WHERE status IN ('deployed','tripped')")
                    .Select(r => (string)r[0]!).ToHashSet(StringComparer.OrdinalIgnoreCase);
            }
            catch (SqliteException) { return new HashSet<string>(); }
        }
        // Refresh the decoy list at most every 30 s; the ETW callback is hot.
        IReadOnlySet<string> cached = new HashSet<string>(); long at = 0;
        var sources = etw ? EtwCollectors.Create(MachineInfo.BootId(), () =>
        {
            long now = Environment.TickCount64;
            if (now - at > 30_000) { cached = DecoyPaths(); at = now; }
            return cached;
        }) : [];
        return CoreHost.RunAsync(paths, sources, m => log.LogInformation("{Message}", m), ct);
    }
}
