using System.Security.Cryptography;
using System.Text;

namespace Hannibal.Core.Storage;

/// <summary>
/// "Bronze record" (Fu Hao motif): an append-only hash chain. It makes
/// tampering EVIDENT to a verifier that holds a later head; it does not make
/// tampering impossible for a local administrator.
/// </summary>
public sealed class AuditChain(SqliteDb db)
{
    public static readonly string Genesis = new('0', 64);

    public static string Hash(string prev, long ms, string kind, string body)
    {
        var bytes = Encoding.UTF8.GetBytes(prev + "\u001f" + ms + "\u001f" + kind + "\u001f" + body);
        return Convert.ToHexStringLower(SHA256.HashData(bytes));
    }

    public string Append(long nowMs, string kind, string bodyJson)
    {
        string head = Genesis;
        db.Transact(() =>
        {
            head = Head();
            var h = Hash(head, nowMs, kind, bodyJson);
            db.Execute(
                "INSERT INTO audit_chain(recorded_ms,kind,body_json,prev_hash,entry_hash) VALUES(?,?,?,?,?)",
                nowMs, kind, bodyJson, head, h);
            head = h;
        });
        return head;
    }

    public string Head() =>
        (string?)db.Scalar("SELECT entry_hash FROM audit_chain ORDER BY audit_seq DESC LIMIT 1") ?? Genesis;

    public long Count() => (long)db.Scalar("SELECT COUNT(*) FROM audit_chain")!;

    /// <summary>Returns the audit_seq of the first broken link, or null if intact.</summary>
    public long? FirstBrokenLink()
    {
        string prev = Genesis;
        foreach (var r in db.Query(
            "SELECT audit_seq,recorded_ms,kind,body_json,prev_hash,entry_hash FROM audit_chain ORDER BY audit_seq"))
        {
            if ((string)r[4]! != prev) return (long)r[0]!;
            var expect = Hash(prev, (long)r[1]!, (string)r[2]!, (string)r[3]!);
            if (expect != (string)r[5]!) return (long)r[0]!;
            prev = expect;
        }
        return null;
    }
}
