using System.ComponentModel;
using System.Text;
using System.Text.RegularExpressions;
using ModelContextProtocol.Server;

namespace UnityLogsServer;

/// <summary>
/// The four tools both MCP transports expose. Every answer stays under 400 lines and 60 000 characters so it fits into a model's context.
/// </summary>
[McpServerToolType]
public sealed class LogTools(LogStore store)
{
    private const int MaxLines = 400;
    private const int MaxChars = 60_000;
    private const int MaxHitChars = 300;    // One search hit; a stack trace can be a single very long line.
    private const string TokenNote = "# note: personal data is shown as [pii:…] tokens, this server holds no private key.";

    [McpServerTool(Name = "list_logs", ReadOnly = true)]
    [Description("Lists uploaded Unity logs, newest first, with device, upload reason and app version.")]
    public string ListLogs(
        [Description("How many days back to look; 0 for all.")] int days = 7,
        [Description("Only logs of this device id (the hashed id MCPLogger sends).")] string? deviceId = null,
        [Description("Only logs with this upload reason, e.g. quit, pause, manual.")] string? reason = null)
    {
        var answer = new Answer();
        answer.Line("id | received (UTC) | reason | device | device_id | app_version | KB | truncated");

        foreach (LogMeta m in Filter(days, deviceId, reason))
            if (!answer.Line($"{m.Id} | {m.ReceivedAt:yyyy-MM-dd HH:mm:ss} | {m.Get("reason")} | {m.Get("device")} | {m.Get("device_id")} | {m.Get("app_version")} | {m.Bytes / 1024} | {(m.Truncated ? "yes" : "no")}"))
                return answer + "… more logs, narrow the query with days, deviceId or reason.";

        return answer.ToString();
    }

    [McpServerTool(Name = "read_log", ReadOnly = true)]
    [Description("Reads one log by id, a page of lines at a time.")]
    public string ReadLog(
        [Description("Log id from list_logs, e.g. 2026-10-29/142233-3f9a….")] string id,
        [Description("First line to return, 0-based.")] int offset = 0,
        [Description("Number of lines to return, at most 400.")] int lines = MaxLines)
    {
        string? text = store.ReadText(id);
        if (text == null) return $"No log with id '{id}'.";

        string[] all = text.Split('\n');
        offset = Math.Clamp(offset, 0, all.Length);
        int end = Math.Min(all.Length, offset + Math.Clamp(lines, 1, MaxLines));

        var answer = new Answer();
        if (!store.CanDecrypt) answer.Line(TokenNote);
        LogMeta? meta = store.ReadMeta(id);
        answer.Line($"# {id} | {meta?.Get("device")} | device_id {meta?.Get("device_id")} | lines {offset}-{end - 1} of {all.Length}{(meta?.Truncated == true ? " | truncated on upload" : "")}");

        int i = offset;
        while (i < end && answer.Line(all[i].TrimEnd('\r'))) i++;

        return i < all.Length ? answer + $"# more: read_log(id, offset={i})" : answer.ToString();
    }

    [McpServerTool(Name = "search_logs", ReadOnly = true)]
    [Description("Searches lines across logs, newest log first. Where this server holds the private key, personal data is decrypted before matching, so real names can be searched.")]
    public string SearchLogs(
        [Description("Text to find, case-insensitive.")] string query,
        [Description("Treat query as a .NET regular expression.")] bool regex = false,
        [Description("How many days back to look; 0 for all.")] int days = 7,
        [Description("Only logs of this device id.")] string? deviceId = null)
    {
        Regex matcher;
        try { matcher = new Regex(regex ? query : Regex.Escape(query), RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1)); }
        catch (ArgumentException ex) { return $"Invalid regular expression: {ex.Message}"; }

        var answer = new Answer();
        if (!store.CanDecrypt) answer.Line(TokenNote);
        int hits = 0;

        foreach (LogMeta m in Filter(days, deviceId, null))
        {
            string[] lines = store.ReadText(m.Id)?.Split('\n') ?? [];

            for (int n = 0; n < lines.Length; n++)
            {
                try { if (!matcher.IsMatch(lines[n])) continue; }
                catch (RegexMatchTimeoutException) { return "The regular expression is too slow, simplify it."; }

                string line = lines[n].TrimEnd('\r');
                if (line.Length > MaxHitChars) line = line[..MaxHitChars] + "…";
                if (!answer.Line($"{m.Id}:{n}: {line}")) return answer + "… more hits, narrow the query.";
                hits++;
            }
        }

        return hits == 0 ? "No hits." : answer.ToString();
    }

    [McpServerTool(Name = "log_stats", ReadOnly = true)]
    [Description("Counts logs per day, upload reason and device.")]
    public string LogStats([Description("How many days back to look; 0 for all.")] int days = 30)
    {
        List<LogMeta> metas = store.List(days);
        var answer = new Answer();
        answer.Line($"logs: {metas.Count}, {metas.Sum(m => m.Bytes) / 1024} KB, truncated: {metas.Count(m => m.Truncated)}");

        Group("per day", m => m.Id[..10]);
        Group("per reason", m => m.Get("reason"));
        Group("per device", m => $"{m.Get("device_id")} ({m.Get("device")})");

        return answer.ToString();

        void Group(string title, Func<LogMeta, string> key)
        {
            answer.Line($"{title}:");
            foreach (var group in metas.GroupBy(key).OrderByDescending(g => g.Count()))
                answer.Line($"  {group.Key}: {group.Count()}");
        }
    }

    private IEnumerable<LogMeta> Filter(int days, string? deviceId, string? reason) =>
        store.List(days).Where(m => (string.IsNullOrEmpty(deviceId) || m.Get("device_id") == deviceId)
                                 && (string.IsNullOrEmpty(reason) || m.Get("reason") == reason));

    /// <summary>
    /// Collects answer lines until the limits are reached, leaving room for one closing hint.
    /// </summary>
    private sealed class Answer
    {
        private readonly StringBuilder text = new();
        private int lines;

        public bool Line(string line)
        {
            if (lines >= MaxLines - 1 || text.Length + line.Length > MaxChars - 200) return false;

            text.AppendLine(line);
            lines++;
            return true;
        }

        public override string ToString() => text.ToString();
    }
}
