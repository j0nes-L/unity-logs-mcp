using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace UnityLogsServer;

public sealed record LogMeta(string Id, DateTime ReceivedAt, long Bytes, bool Truncated, Dictionary<string, string> Query)
{
    public string Get(string key) => Query.TryGetValue(key, out string? value) ? value : "";
}

public sealed partial class LogStore(string root, LogPrivacy privacy)
{
    public bool CanDecrypt => privacy.HasKeys;

    public string Save(byte[] body, bool truncated, Dictionary<string, string> query)
    {
        string session = query.TryGetValue("session", out string? s) && SessionName().IsMatch(s)
            ? s
            : Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(8));

        // A run uploads its whole log again on every pause and on quit; the newest upload replaces the earlier ones.
        string? path = Directory.Exists(root)
            ? Directory.EnumerateFiles(root, $"*-{session}.log", SearchOption.AllDirectories).FirstOrDefault()
            : null;

        DateTime now = DateTime.UtcNow;
        path ??= Path.Combine(root, now.ToString("yyyy-MM-dd"), $"{now:HHmmss}-{session}.log");
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);

        string id = $"{Path.GetFileName(Path.GetDirectoryName(path))}/{Path.GetFileNameWithoutExtension(path)}";
        WriteAtomic(path, body);
        WriteAtomic(Path.ChangeExtension(path, ".json"), JsonSerializer.SerializeToUtf8Bytes(new LogMeta(id, now, body.Length, truncated, query)));

        return id;
    }

    /// <summary>
    /// Metadata of the logs from the last <paramref name="days"/> days (0 = all), newest upload first.
    /// </summary>
    public List<LogMeta> List(int days)
    {
        if (!Directory.Exists(root)) return [];

        string oldest = days > 0 ? DateTime.UtcNow.AddDays(1 - days).ToString("yyyy-MM-dd") : "";

        return Directory.GetDirectories(root)
            .Where(dir => DateDir().IsMatch(Path.GetFileName(dir)) && string.CompareOrdinal(Path.GetFileName(dir), oldest) >= 0)
            .SelectMany(dir => Directory.GetFiles(dir, "*.json"))
            .Select(ReadMetaFile)
            .OfType<LogMeta>()
            .OrderByDescending(meta => meta.ReceivedAt)
            .ToList();
    }

    public LogMeta? ReadMeta(string id) => TryResolve(id, out string path) ? ReadMetaFile(Path.ChangeExtension(path, ".json")) : null;

    /// <summary>
    /// The one entry point for log text: decrypted where this process holds the key, tokens otherwise. Nothing is written back.
    /// </summary>
    public string? ReadText(string id) => TryResolve(id, out string path) && File.Exists(path) ? privacy.Reveal(File.ReadAllText(path)) : null;

    public void DeleteOlderThan(int days)
    {
        if (days <= 0 || !Directory.Exists(root)) return;

        string oldest = DateTime.UtcNow.AddDays(-days).ToString("yyyy-MM-dd");

        foreach (string dir in Directory.GetDirectories(root))
            if (DateDir().IsMatch(Path.GetFileName(dir)) && string.CompareOrdinal(Path.GetFileName(dir), oldest) < 0)
                Directory.Delete(dir, recursive: true);
    }

    /// <summary>
    /// Maps an id to its file, refusing anything that is not exactly date/name, so an id can never leave the log folder.
    /// </summary>
    private bool TryResolve(string id, out string path)
    {
        path = Path.Combine(root, id + ".log");
        return LogId().IsMatch(id);
    }

    private static LogMeta? ReadMetaFile(string file)
    {
        try { return JsonSerializer.Deserialize<LogMeta>(File.ReadAllBytes(file)); }
        catch (Exception ex) when (ex is IOException or JsonException) { return null; }
    }

    /// <summary>
    /// Readers never see a half-written log.
    /// </summary>
    private static void WriteAtomic(string path, byte[] data)
    {
        string temp = path + ".tmp";
        File.WriteAllBytes(temp, data);
        File.Move(temp, path, overwrite: true);
    }

    [GeneratedRegex(@"^[A-Za-z0-9]{1,64}$")]   // No dashes, so one session can never match the file name pattern of another.
    private static partial Regex SessionName();

    [GeneratedRegex(@"^\d{4}-\d{2}-\d{2}$")]
    private static partial Regex DateDir();

    [GeneratedRegex(@"^\d{4}-\d{2}-\d{2}/\d{6}-[A-Za-z0-9]{1,64}$")]
    private static partial Regex LogId();
}
