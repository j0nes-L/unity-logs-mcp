using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace UnityLogsServer;

public sealed partial class LogPrivacy
{
    private readonly Dictionary<string, RSA> keys = new();   // Private keys by kid; several at once, so logs written before a key rotation stay readable.

    public bool HasKeys => keys.Count > 0;

    /// <summary>
    /// Loads every PEM file listed in LOG_PRIVATE_KEY_FILES (comma separated).
    /// </summary>
    public static LogPrivacy FromEnvironment()
    {
        var privacy = new LogPrivacy();
        string files = Environment.GetEnvironmentVariable("LOG_PRIVATE_KEY_FILES") ?? "";

        foreach (string file in files.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            privacy.AddKey(File.ReadAllText(file));

        return privacy;
    }

    public void AddKey(string privateKeyPem)
    {
        var rsa = RSA.Create();
        rsa.ImportFromPem(privateKeyPem);
        keys[KeyId(rsa)] = rsa;
    }

    /// <summary>
    /// Same id as the client writes into the "# pii key" line: the first 8 hex digits of SHA-256 over the modulus.
    /// </summary>
    public static string KeyId(RSA rsa) => Convert.ToHexStringLower(SHA256.HashData(rsa.ExportParameters(false).Modulus!))[..8];

    /// <summary>
    /// Replaces every token this server can open with its plaintext. Tokens that fail the check stay as they are.
    /// </summary>
    public string Reveal(string text)
    {
        if (keys.Count == 0) return text;

        var sessionKeys = new List<byte[]>();
        foreach (Match line in KeyLine().Matches(text))
        {
            if (!keys.TryGetValue(line.Groups[1].Value, out RSA? rsa)) continue;

            try { sessionKeys.Add(rsa.Decrypt(Convert.FromBase64String(line.Groups[2].Value), RSAEncryptionPadding.OaepSHA1)); }
            catch (Exception ex) when (ex is CryptographicException or FormatException) { }
        }

        if (sessionKeys.Count == 0) return text;

        return Token().Replace(text, token => TryDecrypt(token.Groups[1].Value, sessionKeys) ?? token.Value);
    }

    /// <summary>
    /// Opens one token: base64url(iv | AES-256-CBC(plain)) with iv = HMAC-SHA256(macKey, plain)[0..16].
    /// </summary>
    private static string? TryDecrypt(string base64Url, List<byte[]> sessionKeys)
    {
        byte[] blob;
        try { blob = Base64Url.DecodeFromChars(base64Url); }
        catch (FormatException) { return null; }

        if (blob.Length < 32 || blob.Length % 16 != 0) return null;

        foreach (byte[] sessionKey in sessionKeys)
        {
            try
            {
                using var aes = Aes.Create();
                aes.Key = sessionKey[..32];
                byte[] plain = aes.DecryptCbc(blob.AsSpan(16), blob.AsSpan(0, 16), PaddingMode.PKCS7);

                // The IV is derived from the plaintext, so recomputing it is the integrity check.
                if (CryptographicOperations.FixedTimeEquals(HMACSHA256.HashData(sessionKey[32..], plain).AsSpan(0, 16), blob.AsSpan(0, 16)))
                    return Encoding.UTF8.GetString(plain);
            }
            catch (CryptographicException) { }
        }

        return null;
    }

    [GeneratedRegex(@"#\s*pii key\s*:\s*v1 kid=([0-9a-f]{8}) ([A-Za-z0-9+/=]+)")]
    private static partial Regex KeyLine();

    [GeneratedRegex(@"\[pii:([A-Za-z0-9_-]+)\]")]
    private static partial Regex Token();
}
