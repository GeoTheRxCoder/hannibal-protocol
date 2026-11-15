// Hannibal Containment Broker host (simulation only). Thin shell over
// Hannibal.Windows.BrokerHost. This process has no code path that blocks
// traffic, moves files or terminates processes.
using Hannibal.Windows;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(o => o.ServiceName = "HannibalBroker");
builder.Services.AddHostedService<BrokerWorker>();
builder.Build().Run();

sealed class BrokerWorker(ILogger<BrokerWorker> log) : BackgroundService
{
    protected override Task ExecuteAsync(CancellationToken ct) =>
        BrokerHost.RunAsync(HostPaths.Default, m => log.LogInformation("{Message}", m), ct);
}
