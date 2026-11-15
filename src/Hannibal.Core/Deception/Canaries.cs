using System.Security.Cryptography;
using System.Text;
using Hannibal.Contracts;
using Hannibal.Core.Storage;

namespace Hannibal.Core.Deception;

public sealed record CanarySpec(string CanaryId, string DecoyKind, string Location, int SizeBytes, string Extension);

/// <summary>
/// "Ambush" (Fu Hao / Trasimene motif; MITRE D3FEND Decoy File, Decoy User
/// Credential). Decoys sit where bulk file encryption reaches first: the top
/// and bottom of directory sort order in user document folders. They are
/// local-only tripwires. Touching one is ONE raw observation, never a verdict.
/// </summary>
public static class CanaryPlanner
{
    private static readonly (string Name, string Ext, string Kind)[] Templates =
    [
        ("!Accounts_Reconciliation", ".xlsx", "file"),
        ("!Contracts_Signed_Archive", ".pdf", "file"),
        ("~Household_Budget_Backup", ".docx", "file"),
        ("zz_Photo_Index", ".jpg", "file"),
        ("zz_Service_Logins_Export", ".csv", "credential_file"),
    ];

    /// <summary>Deterministic for a device seed so a re-plan never duplicates decoys.</summary>
    public static IReadOnlyList<CanarySpec> Plan(string deviceId, IEnumerable<string> userDirectories, byte[] deviceSeed)
    {
        var list = new List<CanarySpec>();
        foreach (var dir in userDirectories.Distinct(StringComparer.OrdinalIgnoreCase))
            foreach (var t in Templates)
            {
                var tag = HannibalStore.StableId("c", deviceId, dir.ToLowerInvariant(), t.Name);
                // Varied sizes above 1 KiB: fixed-size or tiny decoys are easy to fingerprint.
                int size = 2048 + (int)(BitConverter.ToUInt32(Prf(deviceSeed, tag + "|size"), 0) % 180_000);
                var sep = dir.Contains('\\') ? "\\" : "/";
                list.Add(new CanarySpec(tag, t.Kind, dir.TrimEnd('\\', '/') + sep + t.Name + t.Ext, size, t.Ext));
            }
        return list;
    }

    /// <summary>Plausible bytes with the right magic number. Contains no real data.</summary>
    public static byte[] Render(CanarySpec spec, byte[] deviceSeed)
    {
        if (spec.DecoyKind == "credential_file")
        {
            var sb = new StringBuilder("service,username,password,notes\r\n");
            for (int i = 0; sb.Length < spec.SizeBytes; i++)
            {
                var tok = Convert.ToHexStringLower(Prf(deviceSeed, spec.CanaryId + "|row|" + i));
                // Honeytoken values are unique per device and are valid nowhere.
                sb.Append("svc-").Append(tok[..6]).Append(",acct_").Append(tok[6..12]).Append(',')
                  .Append(tok[12..28]).Append(",decoy\r\n");
            }
            return Encoding.ASCII.GetBytes(sb.ToString());
        }
        byte[] magic = spec.Extension switch
        {
            ".pdf" => "%PDF-1.7\n"u8.ToArray(),
            ".jpg" => [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00],
            _ => [0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x06, 0x00] // OOXML container
        };
        var data = new byte[Math.Max(spec.SizeBytes, magic.Length)];
        int off = magic.Length;
        magic.CopyTo(data, 0);
        for (int block = 0; off < data.Length; block++)
        {
            var chunk = Prf(deviceSeed, spec.CanaryId + "|body|" + block);
            int n = Math.Min(chunk.Length, data.Length - off);
            Array.Copy(chunk, 0, data, off, n);
            off += n;
        }
        return data;
    }

    private static byte[] Prf(byte[] seed, string label) => HMACSHA256.HashData(seed, Encoding.UTF8.GetBytes(label));
}

public sealed record CanaryVerdict(bool IsTripwire, double Confidence, string Reason);

public static class CanaryClassifier
{
    /// <summary>Signed tools that legitimately READ every file. Reads by these are expected.</summary>
    public static readonly IReadOnlySet<string> ExpectedReaders = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "MsMpEng.exe", "SearchIndexer.exe", "SearchProtocolHost.exe", "SearchFilterHost.exe",
        "OneDrive.exe", "wbengine.exe", "VSSVC.exe", "HannibalCoreService.exe"
    };

    public static CanaryVerdict Classify(string kind, string actorImageName, string actorSignerStatus)
    {
        bool trusted = actorSignerStatus == "trusted";
        if (kind == ObservationKinds.FileRead)
        {
            if (trusted && ExpectedReaders.Contains(actorImageName)) return new(false, 0, "EXPECTED_SCANNER_READ");
            if (trusted) return new(false, 0, "SIGNED_READER_NOTED");
            return new(true, .60, "DECOY_READ_BY_UNTRUSTED_PROCESS");
        }
        if (kind is ObservationKinds.FileWrite or ObservationKinds.FileRename or ObservationKinds.FileDelete
            or ObservationKinds.DecoyTouch)
        {
            // A person tidying files through the shell is the main benign cause of a modification.
            if (trusted && actorImageName.Equals("explorer.exe", StringComparison.OrdinalIgnoreCase))
                return new(true, .50, "DECOY_MODIFIED_VIA_SHELL");
            return new(true, trusted ? .80 : .95, "DECOY_MODIFIED");
        }
        return new(false, 0, "NOT_A_DECOY_EVENT");
    }
}

/// <summary>
/// Removes deployed decoy files on uninstall. A decoy is deleted only if its
/// bytes still hash to the value recorded at deployment, so a user file that
/// happens to sit at the same path is never touched.
/// </summary>
public static class CanaryCleanup
{
    public sealed record Outcome(int Removed, int AlreadyGone, int KeptChanged, int Failed);

    public static Outcome RemoveAll(HannibalStore store, string deviceId, long nowMs)
    {
        int removed = 0, gone = 0, kept = 0, failed = 0;
        foreach (var c in store.ListCanaries(deviceId).Where(c => c.DecoyKind is "file" or "credential_file"))
        {
            try
            {
                if (!File.Exists(c.Location)) { gone++; store.MarkCanary(c.CanaryId, "retired", nowMs); continue; }
                var sha = Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(c.Location)));
                if (c.Sha256 is null || sha != c.Sha256) { kept++; continue; }
                File.SetAttributes(c.Location, FileAttributes.Normal);
                File.Delete(c.Location);
                store.MarkCanary(c.CanaryId, "retired", nowMs);
                removed++;
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { failed++; }
        }
        return new Outcome(removed, gone, kept, failed);
    }
}
