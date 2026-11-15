using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Hannibal.Core.Identity;
using Hannibal.Core.Ribat;
using Microsoft.Win32.SafeHandles;

[assembly: SupportedOSPlatform("windows")]

namespace Hannibal.Windows;

/// <summary>
/// Authenticode check for EMBEDDED signatures (WinVerifyTrust, no UI, no
/// network retrieval). LIMITATION: catalog-signed files - most of System32 -
/// carry no embedded signature. Until catalog lookup (CryptCATAdmin*) is
/// added, a file under %WINDIR% without an embedded signature is reported
/// "unknown", never "unsigned".
/// </summary>
public static class Authenticode
{
    private static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
    private const int TrustENoSignature = unchecked((int)0x800B0100);

    [StructLayout(LayoutKind.Sequential)]
    private struct WintrustFileInfo { public uint cbStruct; public IntPtr pcwszFilePath, hFile, pgKnownSubject; }

    [StructLayout(LayoutKind.Sequential)]
    private struct WintrustData
    {
        public uint cbStruct; public IntPtr pPolicyCallbackData, pSIPClientData;
        public uint dwUIChoice, fdwRevocationChecks, dwUnionChoice; public IntPtr pFile;
        public uint dwStateAction; public IntPtr hWVTStateData, pwszURLReference;
        public uint dwProvFlags, dwUIContext; public IntPtr pSignatureSettings;
    }

    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid action, ref WintrustData data);

    /// <summary>Returns "trusted", "unsigned", "invalid" or "unknown".</summary>
    public static string Status(string path)
    {
        IntPtr pPath = IntPtr.Zero, pFile = IntPtr.Zero;
        try
        {
            pPath = Marshal.StringToCoTaskMemUni(path);
            var fi = new WintrustFileInfo { cbStruct = (uint)Marshal.SizeOf<WintrustFileInfo>(), pcwszFilePath = pPath };
            pFile = Marshal.AllocCoTaskMem(Marshal.SizeOf<WintrustFileInfo>());
            Marshal.StructureToPtr(fi, pFile, false);
            var data = new WintrustData
            {
                cbStruct = (uint)Marshal.SizeOf<WintrustData>(), dwUIChoice = 2 /* WTD_UI_NONE */,
                fdwRevocationChecks = 0, dwUnionChoice = 1 /* WTD_CHOICE_FILE */, pFile = pFile,
                dwStateAction = 1 /* VERIFY */, dwProvFlags = 0x1000 /* WTD_CACHE_ONLY_URL_RETRIEVAL */
            };
            var action = GenericVerifyV2;
            int rc = WinVerifyTrust(IntPtr.Zero, ref action, ref data);
            data.dwStateAction = 2; // CLOSE
            WinVerifyTrust(IntPtr.Zero, ref action, ref data);
            if (rc == 0) return "trusted";
            if (rc != TrustENoSignature) return "invalid";
            var win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            return path.StartsWith(win, StringComparison.OrdinalIgnoreCase) ? "unknown" : "unsigned";
        }
        catch (Exception e) when (e is DllNotFoundException or EntryPointNotFoundException or IOException) { return "unknown"; }
        finally
        {
            if (pFile != IntPtr.Zero) Marshal.FreeCoTaskMem(pFile);
            if (pPath != IntPtr.Zero) Marshal.FreeCoTaskMem(pPath);
        }
    }

    /// <summary>Signer subject, read ONLY after WinVerifyTrust reported "trusted". Never a trust decision by itself.</summary>
    public static string? SignerSubject(string path)
    {
        try
        {
#pragma warning disable SYSLIB0057 // legacy loader is adequate for reading the subject of an already-verified file
            using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
#pragma warning restore SYSLIB0057
            return cert.Subject;
        }
        catch (CryptographicException) { return null; }
    }
}

/// <summary>
/// Stable file identity (volume serial + 128-bit file ID) and a SHA-256 taken
/// from the SAME handle, opened without write sharing, with the identity
/// re-read afterwards. This narrows, and does not eliminate, TOCTOU windows.
/// </summary>
public sealed class FileIdentityProbe : IFileProbe
{
    [StructLayout(LayoutKind.Sequential)]
    private struct FileIdInfo { public ulong VolumeSerialNumber, FileIdLow, FileIdHigh; }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle h, int infoClass, out FileIdInfo info, uint size);

    private static readonly string[] ProtectedPublishers = ["O=Microsoft Corporation", "O=Microsoft Windows"];

    public static string? IdentityOf(SafeFileHandle h) =>
        GetFileInformationByHandleEx(h, 18 /* FileIdInfo */, out var i, (uint)Marshal.SizeOf<FileIdInfo>())
            ? IdentityKeys.FileOccurrence(i.VolumeSerialNumber.ToString("x16"), i.FileIdHigh.ToString("x16") + i.FileIdLow.ToString("x16"))
            : null;

    public FileProbeResult? Probe(string path)
    {
        try
        {
            using var h = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            var before = IdentityOf(h);
            if (before is null) return null;
            // Hash through the handle itself (no FileStream, which would close it before the re-check).
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            var buffer = new byte[1 << 16];
            long offset = 0;
            for (int n; (n = RandomAccess.Read(h, buffer, offset)) > 0; offset += n) hash.AppendData(buffer, 0, n);
            string sha = Convert.ToHexStringLower(hash.GetHashAndReset());
            if (IdentityOf(h) != before) return null; // handle binding could not be confirmed
            bool protectedPublisher = Authenticode.Status(path) == "trusted" &&
                Authenticode.SignerSubject(path) is string s && ProtectedPublishers.Any(p => s.Contains(p, StringComparison.OrdinalIgnoreCase));
            return new FileProbeResult(before, sha, protectedPublisher);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException) { return null; }
    }
}
