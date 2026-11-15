using System.Reflection;
using System.Runtime.InteropServices;

namespace Hannibal.Core.Storage;

/// <summary>
/// Minimal SQLite binding with no NuGet dependency. Resolves winsqlite3.dll
/// (ships with Windows 10/11) on Windows and libsqlite3 elsewhere. One
/// connection, serialized by a lock; write transactions use BEGIN IMMEDIATE.
/// </summary>
public sealed class SqliteDb : IDisposable
{
    private const string Lib = "hannibal_sqlite";
    private const int Ok = 0, Row = 100, Done = 101;
    private static readonly IntPtr Transient = new(-1);
    private readonly object _gate = new();
    private IntPtr _db;
    private int _txDepth;

    static SqliteDb()
    {
        NativeLibrary.SetDllImportResolver(typeof(SqliteDb).Assembly, Resolve);
    }

    private static IntPtr Resolve(string name, Assembly asm, DllImportSearchPath? path)
    {
        if (name != Lib) return IntPtr.Zero;
        string[] candidates = OperatingSystem.IsWindows()
            ? ["e_sqlite3", "winsqlite3"]
            : OperatingSystem.IsMacOS() ? ["libsqlite3.dylib"] : ["libsqlite3.so.0", "libsqlite3.so"];
        foreach (var c in candidates)
            if (NativeLibrary.TryLoad(c, asm, path, out var h)) return h;
        throw new DllNotFoundException("No SQLite library found (tried " + string.Join(", ", candidates) + ").");
    }

    public static SqliteDb Open(string path, bool readOnly = false)
    {
        // READWRITE|CREATE = 6, READONLY = 1, FULLMUTEX = 0x10000
        int flags = (readOnly ? 1 : 6) | 0x10000;
        int rc = sqlite3_open_v2(path, out var db, flags, IntPtr.Zero);
        var self = new SqliteDb { _db = db };
        if (rc != Ok) { var msg = self.Err(); self.Dispose(); throw new SqliteException(rc, msg); }
        sqlite3_busy_timeout(db, 5000);
        self.Exec("PRAGMA foreign_keys=ON;");
        return self;
    }

    public void Exec(string sql)
    {
        lock (_gate)
        {
            int rc = sqlite3_exec(_db, sql, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
            if (rc != Ok) throw new SqliteException(rc, Err());
        }
    }

    public int Execute(string sql, params object?[] args)
    {
        lock (_gate)
        {
            var st = Prepare(sql, args);
            try
            {
                int rc = sqlite3_step(st);
                while (rc == Row) rc = sqlite3_step(st);
                if (rc != Done) throw new SqliteException(rc, Err());
                return sqlite3_changes(_db);
            }
            finally { sqlite3_finalize(st); }
        }
    }

    public List<object?[]> Query(string sql, params object?[] args)
    {
        lock (_gate)
        {
            var st = Prepare(sql, args);
            try
            {
                var rows = new List<object?[]>();
                int n = sqlite3_column_count(st), rc;
                while ((rc = sqlite3_step(st)) == Row)
                {
                    var r = new object?[n];
                    for (int i = 0; i < n; i++)
                        r[i] = sqlite3_column_type(st, i) switch
                        {
                            1 => sqlite3_column_int64(st, i),
                            2 => sqlite3_column_double(st, i),
                            3 => Marshal.PtrToStringUTF8(sqlite3_column_text(st, i)),
                            5 => null,
                            _ => throw new SqliteException(-1, "Unsupported column type")
                        };
                    rows.Add(r);
                }
                if (rc != Done) throw new SqliteException(rc, Err());
                return rows;
            }
            finally { sqlite3_finalize(st); }
        }
    }

    public object? Scalar(string sql, params object?[] args)
    {
        var rows = Query(sql, args);
        return rows.Count == 0 ? null : rows[0][0];
    }

    public long LastInsertRowId { get { lock (_gate) return sqlite3_last_insert_rowid(_db); } }

    /// <summary>Atomic unit. Nested calls join the outer transaction.</summary>
    public void Transact(Action body)
    {
        lock (_gate)
        {
            if (_txDepth > 0) { body(); return; }
            Exec("BEGIN IMMEDIATE;");
            _txDepth++;
            try { body(); _txDepth--; Exec("COMMIT;"); }
            catch { _txDepth = 0; try { Exec("ROLLBACK;"); } catch (SqliteException) { } throw; }
        }
    }

    private IntPtr Prepare(string sql, object?[] args)
    {
        int rc = sqlite3_prepare_v2(_db, sql, -1, out var st, IntPtr.Zero);
        if (rc != Ok) throw new SqliteException(rc, Err() + " :: " + sql);
        for (int i = 0; i < args.Length; i++)
        {
            int idx = i + 1;
            rc = args[i] switch
            {
                null => sqlite3_bind_null(st, idx),
                long l => sqlite3_bind_int64(st, idx, l),
                int n => sqlite3_bind_int64(st, idx, n),
                bool b => sqlite3_bind_int64(st, idx, b ? 1 : 0),
                double d => sqlite3_bind_double(st, idx, d),
                string s => sqlite3_bind_text(st, idx, s, -1, Transient),
                _ => throw new ArgumentException("Unsupported parameter type " + args[i]!.GetType())
            };
            if (rc != Ok) { sqlite3_finalize(st); throw new SqliteException(rc, Err()); }
        }
        return st;
    }

    private string Err() => _db == IntPtr.Zero ? "open failed"
        : Marshal.PtrToStringUTF8(sqlite3_errmsg(_db)) ?? "unknown";

    public void Dispose()
    {
        lock (_gate)
        {
            if (_db != IntPtr.Zero) { sqlite3_close_v2(_db); _db = IntPtr.Zero; }
        }
    }

    [DllImport(Lib)] private static extern int sqlite3_open_v2([MarshalAs(UnmanagedType.LPUTF8Str)] string f, out IntPtr db, int flags, IntPtr vfs);
    [DllImport(Lib)] private static extern int sqlite3_close_v2(IntPtr db);
    [DllImport(Lib)] private static extern int sqlite3_busy_timeout(IntPtr db, int ms);
    [DllImport(Lib)] private static extern int sqlite3_exec(IntPtr db, [MarshalAs(UnmanagedType.LPUTF8Str)] string sql, IntPtr cb, IntPtr arg, IntPtr err);
    [DllImport(Lib)] private static extern int sqlite3_prepare_v2(IntPtr db, [MarshalAs(UnmanagedType.LPUTF8Str)] string sql, int n, out IntPtr st, IntPtr tail);
    [DllImport(Lib)] private static extern int sqlite3_step(IntPtr st);
    [DllImport(Lib)] private static extern int sqlite3_finalize(IntPtr st);
    [DllImport(Lib)] private static extern int sqlite3_changes(IntPtr db);
    [DllImport(Lib)] private static extern long sqlite3_last_insert_rowid(IntPtr db);
    [DllImport(Lib)] private static extern IntPtr sqlite3_errmsg(IntPtr db);
    [DllImport(Lib)] private static extern int sqlite3_bind_null(IntPtr st, int i);
    [DllImport(Lib)] private static extern int sqlite3_bind_int64(IntPtr st, int i, long v);
    [DllImport(Lib)] private static extern int sqlite3_bind_double(IntPtr st, int i, double v);
    [DllImport(Lib)] private static extern int sqlite3_bind_text(IntPtr st, int i, [MarshalAs(UnmanagedType.LPUTF8Str)] string v, int n, IntPtr d);
    [DllImport(Lib)] private static extern int sqlite3_column_count(IntPtr st);
    [DllImport(Lib)] private static extern int sqlite3_column_type(IntPtr st, int i);
    [DllImport(Lib)] private static extern long sqlite3_column_int64(IntPtr st, int i);
    [DllImport(Lib)] private static extern double sqlite3_column_double(IntPtr st, int i);
    [DllImport(Lib)] private static extern IntPtr sqlite3_column_text(IntPtr st, int i);
}

public sealed class SqliteException(int code, string message)
    : Exception($"SQLite error {code}: {message}")
{
    public int Code { get; } = code;
}
