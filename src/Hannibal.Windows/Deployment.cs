using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using Hannibal.Core.Deception;
using Hannibal.Core.Storage;
using Microsoft.Win32;

namespace Hannibal.Windows;

public static class MachineInfo
{
    /// <summary>Stable, non-reversible device identifier derived from MachineGuid.</summary>
    public static string DeviceId()
    {
        var guid = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography", "MachineGuid", null) as string
                   ?? Environment.MachineName;
        return "dev-" + HannibalStore.StableId("d", guid)[2..18];
    }

    /// <summary>Boot session identifier: system boot time rounded to the second.</summary>
    public static string BootId() =>
        "boot-" + (DateTimeOffset.UtcNow.ToUnixTimeSeconds() - Environment.TickCount64 / 1000).ToString();
}

public static class SecureFiles
{
    /// <summary>Creates a directory readable only by SYSTEM, Administrators and the listed accounts.</summary>
    public static void RestrictDirectory(string path, params string[] readAccounts)
    {
        var dir = Directory.CreateDirectory(path);
        var sec = new DirectorySecurity();
        sec.SetAccessRuleProtection(true, false);
        const InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        sec.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        sec.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        foreach (var a in readAccounts)
            sec.AddAccessRule(new FileSystemAccessRule(new NTAccount(a), FileSystemRights.ReadAndExecute, inherit,
                PropagationFlags.None, AccessControlType.Allow));
        dir.SetAccessControl(sec);
    }

    /// <summary>
    /// Per-install IPC key. ACLs here slow down an ordinary process; they do
    /// not stop a local administrator, who must be treated as an advanced adversary.
    /// </summary>
    public static byte[] LoadOrCreateSessionKey(string path)
    {
        if (File.Exists(path) && File.ReadAllBytes(path) is { Length: 32 } existing) return existing;
        var key = RandomNumberGenerator.GetBytes(32);
        File.WriteAllBytes(path, key);
        return key;
    }
}

public sealed record DeployedDecoy(CanarySpec Spec, string FileIdentityKey, string Sha256);

/// <summary>
/// Writes decoy files. Hidden and excluded from content indexing; never
/// System-flagged; never placed in a cloud-synced folder; never overwrites an
/// existing file. Every decoy is listed in the manifest so it can be removed.
/// </summary>
public static class CanaryDeployer
{
    public static IEnumerable<string> UserDocumentDirectories()
    {
        var users = Path.Combine(Path.GetPathRoot(Environment.SystemDirectory) ?? @"C:\", "Users");
        if (!Directory.Exists(users)) yield break;
        foreach (var profile in Directory.EnumerateDirectories(users))
        {
            var name = Path.GetFileName(profile);
            if (name is "Public" or "Default" or "Default User" or "All Users") continue;
            foreach (var sub in new[] { "Documents", "Desktop", "Pictures" })
            {
                var d = Path.Combine(profile, sub);
                if (!Directory.Exists(d)) continue;
                // A reparse point here usually means Known Folder Move into OneDrive: skip it.
                if ((File.GetAttributes(d) & FileAttributes.ReparsePoint) != 0) continue;
                yield return d;
            }
        }
    }

    public static List<DeployedDecoy> Deploy(IEnumerable<CanarySpec> plan, byte[] deviceSeed)
    {
        var done = new List<DeployedDecoy>();
        foreach (var spec in plan)
        {
            try
            {
                if (spec.Location.Contains("OneDrive", StringComparison.OrdinalIgnoreCase)) continue;
                if (!File.Exists(spec.Location))
                {
                    var bytes = CanaryPlanner.Render(spec, deviceSeed);
                    using (var fs = new FileStream(spec.Location, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                        fs.Write(bytes);
                    File.SetAttributes(spec.Location, FileAttributes.Hidden | FileAttributes.NotContentIndexed);
                    // Plausible age: decoys that all share one creation second are easy to spot.
                    var age = DateTime.UtcNow.AddDays(-30 - bytes[^1] % 300);
                    File.SetCreationTimeUtc(spec.Location, age);
                    File.SetLastWriteTimeUtc(spec.Location, age.AddDays(bytes[^2] % 20));
                }
                using var h = File.OpenHandle(spec.Location, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                var id = FileIdentityProbe.IdentityOf(h);
                if (id is null) continue;
                using var rs = new FileStream(h, FileAccess.Read);
                done.Add(new DeployedDecoy(spec, id, Convert.ToHexStringLower(SHA256.HashData(rs))));
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { /* skip this location */ }
        }
        return done;
    }

    /// <summary>Removes a decoy only if its content still matches what was deployed.</summary>
    public static bool Remove(string location, string expectedSha256)
    {
        try
        {
            if (!File.Exists(location)) return true;
            if (Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(location))) != expectedSha256) return false;
            File.SetAttributes(location, FileAttributes.Normal);
            File.Delete(location);
            return true;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return false; }
    }
}

/// <summary>Maps NT device paths (\Device\HarddiskVolume3\...) reported by ETW to drive-letter paths.</summary>
public static class DevicePaths
{
    [System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode, SetLastError = true)]
    private static extern uint QueryDosDevice(string deviceName, [System.Runtime.InteropServices.Out] char[] targetPath, uint max);

    private static readonly Lazy<List<(string Device, string Drive)>> Map = new(() =>
    {
        var list = new List<(string, string)>();
        var buf = new char[512];
        foreach (var d in DriveInfo.GetDrives())
        {
            string drive = d.Name.TrimEnd('\\');
            uint n = QueryDosDevice(drive, buf, (uint)buf.Length);
            if (n > 0) list.Add((new string(buf, 0, Array.IndexOf(buf, '\0')), drive));
        }
        return list;
    });

    public static string ToDosPath(string ntPath)
    {
        foreach (var (device, drive) in Map.Value)
            if (ntPath.StartsWith(device + "\\", StringComparison.OrdinalIgnoreCase))
                return drive + ntPath[device.Length..];
        return ntPath;
    }
}
