using System.Security.Cryptography;
using System.Text;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Http.Features;
using UnityLogsServer;

const int MaxLogBytes = 20 * 1024 * 1024;       // Bigger logs are cut, not rejected; the end survives because that is where the crash is.
const long MaxBodyBytes = 100L * 1024 * 1024;   // Past this an upload is refused, so nobody can stream into the server forever.
const int MaxQueryValueChars = 200;

var store = new LogStore(Environment.GetEnvironmentVariable("LOG_DIR") ?? "/data/logs", LogPrivacy.FromEnvironment());

// stdio: started by Claude Code for one session, next to the private key, and answers in plain text.
if (args.Contains("--stdio"))
{
    var stdio = Host.CreateApplicationBuilder(args);
    stdio.Logging.ClearProviders();   // stdout carries the protocol, a single log line would break it.
    stdio.Services.AddSingleton(store);
    stdio.Services.AddMcpServer().WithStdioServerTransport().WithTools<LogTools>();
    await stdio.Build().RunAsync();
    return;
}

string unityAccessKey = Require("UNITY_ACCESS_KEY");
string mcpToken = Require("MCP_TOKEN");
int retentionDays = int.TryParse(Environment.GetEnvironmentVariable("LOG_RETENTION_DAYS"), out int days) ? days : 30;
int uploadsPerMinute = int.TryParse(Environment.GetEnvironmentVariable("RATE_LIMIT_PER_MINUTE"), out int limit) ? limit : 30;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddSingleton(store);
builder.Services.AddMcpServer().WithHttpTransport(o => o.Stateless = true).WithTools<LogTools>();
builder.Services.AddRateLimiter(o =>
{
    o.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    o.AddPolicy("uploads", ctx => RateLimitPartition.GetFixedWindowLimiter(
        ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
        _ => new FixedWindowRateLimiterOptions { PermitLimit = uploadsPerMinute, Window = TimeSpan.FromMinutes(1) }));
});

var app = builder.Build();
app.UseRateLimiter();

// The MCP endpoint takes only the MCP token. The Unity access key ships inside development builds, so it may upload but never read.
app.Use(async (ctx, next) =>
{
    if (ctx.Request.Path.StartsWithSegments("/mcp") && !SecretMatches(ctx.Request.Headers.Authorization.ToString(), "Bearer " + mcpToken))
    {
        ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
        return;
    }

    await next();
});

app.MapMcp("/mcp");
app.MapGet("/health", () => "ok");

// Body: the raw log text, no multipart, so a client on its way down has as little to do as possible.
app.MapPost("/logs", async (HttpContext ctx) =>
{
    if (!SecretMatches(ctx.Request.Headers["X-Access-Key"].ToString(), unityAccessKey)) return Results.Unauthorized();

    var bodyLimit = ctx.Features.Get<IHttpMaxRequestBodySizeFeature>();
    if (bodyLimit is { IsReadOnly: false }) bodyLimit.MaxRequestBodySize = MaxBodyBytes;

    var (body, truncated) = await ReadTail(ctx.Request.Body, MaxLogBytes, ctx.RequestAborted);
    if (body.Length == 0) return Results.BadRequest("empty log");

    var query = new Dictionary<string, string>();
    foreach (var (key, value) in ctx.Request.Query.Take(20))
        query[Clip(key, 64)] = Clip(value.ToString(), MaxQueryValueChars);

    string id = store.Save(body, truncated, query);
    return Results.Json(new { id, truncated }, statusCode: StatusCodes.Status201Created);
}).RequireRateLimiting("uploads");

_ = RunRetention(store, retentionDays, app.Lifetime.ApplicationStopping);
app.Run();

static string Require(string name) =>
    Environment.GetEnvironmentVariable(name) is { Length: > 0 } value ? value : throw new InvalidOperationException($"{name} is not set, run setup.sh.");

static bool SecretMatches(string given, string expected) =>
    CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(given), Encoding.UTF8.GetBytes(expected));

static string Clip(string value, int max) => value.Length > max ? value[..max] : value;

/// Reads the body but keeps only the last maxBytes, starting at a line break so no line or UTF-8 sequence is cut in half.
static async Task<(byte[] Body, bool Truncated)> ReadTail(Stream body, int maxBytes, CancellationToken ct)
{
    var buffer = new MemoryStream();
    bool truncated = false;
    byte[] chunk = new byte[81920];
    int read;

    while ((read = await body.ReadAsync(chunk, ct)) > 0)
    {
        buffer.Write(chunk, 0, read);
        if (buffer.Length > 2L * maxBytes) (buffer, truncated) = (Tail(buffer, maxBytes), true);
    }

    if (buffer.Length > maxBytes) (buffer, truncated) = (Tail(buffer, maxBytes), true);
    if (!truncated) return (buffer.ToArray(), false);

    byte[] data = buffer.ToArray();
    int lineStart = Array.IndexOf(data, (byte)'\n') + 1;
    byte[] marker = Encoding.UTF8.GetBytes($"# [!] truncated by the server - only the last {maxBytes / (1024 * 1024)} MB of the log were kept\n");

    return ([.. marker, .. data.AsSpan(lineStart)], true);
}

static MemoryStream Tail(MemoryStream source, int bytes)
{
    var tail = new MemoryStream();
    tail.Write(source.GetBuffer(), (int)source.Length - bytes, bytes);
    return tail;
}

/// Deletes day folders past the retention once at start and then hourly; 0 days keeps everything.
static async Task RunRetention(LogStore store, int days, CancellationToken stopping)
{
    if (days <= 0) return;

    using var timer = new PeriodicTimer(TimeSpan.FromHours(1));
    try
    {
        do
        {
            try { store.DeleteOlderThan(days); }
            catch (IOException ex) { Console.Error.WriteLine($"retention: {ex.Message}"); }
        }
        while (await timer.WaitForNextTickAsync(stopping));
    }
    catch (OperationCanceledException) { }
}
