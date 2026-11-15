using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Hannibal.Core.Ipc;
using Microsoft.Win32.SafeHandles;

namespace Hannibal.Windows;

/// <summary>
/// Broker pipe server. The ACL admits only LocalSystem and the Core service's
/// own SID; NETWORK is denied; the first instance must be created by us
/// (anti-squatting). Each connection carries exactly one MAC'd frame, and the
/// MAC - not the pipe ACL alone - is what authenticates a request.
/// </summary>
public sealed class BrokerPipeServer(string pipeName, string coreServiceAccount, Func<byte[], byte[]?> handler)
{
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint clientProcessId);

    /// <summary>Optional extra check on the connecting process (PID -> image -> signature).</summary>
    public Func<int, bool>? ClientProcessVerifier { get; set; }

    private PipeSecurity Security()
    {
        var sec = new PipeSecurity();
        sec.SetAccessRuleProtection(true, false);
        sec.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            PipeAccessRights.FullControl, AccessControlType.Allow));
        sec.AddAccessRule(new PipeAccessRule(new NTAccount(coreServiceAccount),
            PipeAccessRights.ReadWrite, AccessControlType.Allow));
        sec.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid, null),
            PipeAccessRights.FullControl, AccessControlType.Deny));
        return sec;
    }

    public async Task RunAsync(CancellationToken ct)
    {
        bool first = true;
        while (!ct.IsCancellationRequested)
        {
            var options = PipeOptions.Asynchronous | (first ? PipeOptions.FirstPipeInstance : PipeOptions.None);
            await using var pipe = NamedPipeServerStreamAcl.Create(pipeName, PipeDirection.InOut, 1,
                PipeTransmissionMode.Byte, options, FrameCodec.MaxFrame + 4, FrameCodec.MaxFrame + 4, Security());
            first = false;
            try
            {
                await pipe.WaitForConnectionAsync(ct);
                if (ClientProcessVerifier is not null &&
                    (!GetNamedPipeClientProcessId(pipe.SafePipeHandle, out uint pid) || !ClientProcessVerifier((int)pid)))
                    continue;
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
                timeout.CancelAfter(TimeSpan.FromSeconds(5));
                var frame = await FrameCodec.ReadFrameAsync(pipe, timeout.Token);
                var reply = frame is null ? null : handler(frame);
                if (reply is not null) await pipe.WriteAsync(reply, timeout.Token);
            }
            catch (IOException) { /* client went away; serve the next one */ }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested) { /* slow client timed out */ }
        }
    }
}

public static class BrokerPipeClient
{
    /// <summary>Transport delegate for <see cref="BrokerClient"/>. Identification-level impersonation only.</summary>
    public static Func<byte[], byte[]?> Transport(string pipeName, int timeoutMs = 3000) => frame =>
    {
        try
        {
            using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.None,
                TokenImpersonationLevel.Identification);
            pipe.Connect(timeoutMs);
            pipe.Write(frame);
            pipe.Flush();
            using var cts = new CancellationTokenSource(timeoutMs);
            return FrameCodec.ReadFrameAsync(pipe, cts.Token).GetAwaiter().GetResult();
        }
        catch (Exception e) when (e is IOException or TimeoutException or UnauthorizedAccessException or OperationCanceledException)
        {
            return null; // the caller records BROKER_UNAVAILABLE and declines the action
        }
    };
}
