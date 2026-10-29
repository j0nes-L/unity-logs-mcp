using System.Security.Cryptography;
using UnityLogsMCP;
using UnityLogsServer;

using var rsa = RSA.Create(2048);
string publicPem = rsa.ExportSubjectPublicKeyInfoPem();   // What `openssl rsa -pubout` writes and setup.sh hands to Unity.
string privatePem = rsa.ExportPkcs8PrivateKeyPem();       // What `openssl genpkey` writes into secrets/.

Check(MCPLogPrivacy.Configure(publicPem), "client accepts the public key");
MCPLogPrivacy.RegisterSensitive("Jonas Ludorf");

string original = "12:00:01 [Log] Jonas Ludorf joined, mail jonas@example.com, path C:/Users/Jonas Ludorf/x\n"
                + "12:00:02 [Error] Jonas Ludorf left\n"
                + $"# pii key      : {MCPLogPrivacy.KeyLine}\n";
string uploaded = MCPLogPrivacy.Redact(original);

Check(!uploaded.Contains("Jonas Ludorf") && !uploaded.Contains("jonas@example.com"), "upload contains no plaintext personal data");
Check(uploaded.Split("[pii:").Length - 1 == 4, "every occurrence became a token");

var withoutKey = new LogPrivacy();
Check(withoutKey.Reveal(uploaded) == uploaded, "without a key the text stays unchanged");

var server = new LogPrivacy();
server.AddKey(privatePem);
Check(server.Reveal(uploaded) == original, "server restores the original log");

string forged = uploaded.Replace("[pii:", "[pii:AAAA");
Check(!server.Reveal(forged).Contains("Jonas Ludorf"), "tampered tokens stay tokens");

using var otherRsa = RSA.Create(2048);
var otherServer = new LogPrivacy();
otherServer.AddKey(otherRsa.ExportPkcs8PrivateKeyPem());
Check(otherServer.Reveal(uploaded) == uploaded, "a foreign key opens nothing");

Console.WriteLine("All privacy round-trip checks passed.");

static void Check(bool ok, string what)
{
    if (ok) return;
    Console.Error.WriteLine($"FAILED: {what}");
    Environment.Exit(1);
}

namespace UnityEngine
{
    /// <summary>
    /// The one Unity API MCPLogPrivacy touches.
    /// </summary>
    public static class Debug
    {
        public static void LogWarning(object message) => Console.Error.WriteLine(message);
    }
}
