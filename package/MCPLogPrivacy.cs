using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using UnityEngine;

namespace UnityLogsMCP
{
    public static class MCPLogPrivacy
    {
        private const string TokenPrefix = "[pii:";   // Opening marker of an encrypted value.
        private const string TokenSuffix = "]";       // Closing marker of an encrypted value.
        private const int MinSensitiveLength = 3;     // Shorter values would match inside ordinary words and numbers.
        private const string EmailPattern = @"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}";   // Email addresses are encrypted even when never registered.
        private const string WordChar = @"[\p{L}\p{N}_\-]";   // Neighbours that make a hit part of a longer word, number or existing token.

        private static readonly object Sync = new();   // Guards all state; uploads run on the main thread, registrations may not.
        private static readonly HashSet<string> SensitiveValues = new(StringComparer.Ordinal);   // Every value registered as personal data.
        private static readonly Dictionary<string, string> TokenCache = new(StringComparer.Ordinal);   // Plaintext to token, the encryption is deterministic per run.
        private static readonly HashSet<string> IgnoredValues = new(StringComparer.OrdinalIgnoreCase) { "User", "Player", "unavailable", "none" };   // Fallback names and placeholders, not personal and too common to encrypt.

        private static Regex matcher;   // Combined matcher over all sensitive values, rebuilt lazily after a registration.
        private static byte[] encKey;   // AES-256 key of this run's session key.
        private static byte[] macKey;   // HMAC-SHA256 key of this run's session key, also derives the synthetic IV.

        public static bool IsActive { get; private set; }   // True once a public key was configured; only then is anything encrypted.

        public static string KeyLine { get; private set; } = "none (no public key configured - personal data is in plain text)";   // Value of the "# pii key" line: version, key id and the RSA-encrypted session key.

        /// <summary>
        /// Draws this run's session key and wraps it with the given RSA public key (PEM, SPKI or PKCS#1); the first successful call wins.
        /// </summary>
        public static bool Configure(string publicKeyPem)
        {
            string failure;

            lock (Sync)
            {
                if (IsActive) return true;
                if (string.IsNullOrWhiteSpace(publicKeyPem)) return false;

                try
                {
                    RSAParameters parameters = ParsePublicKeyPem(publicKeyPem);

                    byte[] sessionKey = new byte[64];
                    using (var rng = new RNGCryptoServiceProvider()) rng.GetBytes(sessionKey);

                    byte[] wrapped;
                    using (var rsa = new RSACryptoServiceProvider())
                    {
                        rsa.ImportParameters(parameters);
                        wrapped = rsa.Encrypt(sessionKey, RSAEncryptionPadding.OaepSHA1);
                    }

                    encKey = sessionKey.Take(32).ToArray();
                    macKey = sessionKey.Skip(32).ToArray();

                    KeyLine = $"v1 kid={KeyId(parameters)} {Convert.ToBase64String(wrapped)}";
                    IsActive = true;
                    TokenCache.Clear();
                    return true;
                }
                catch (Exception ex)
                {
                    failure = ex.Message;
                }
            }

            Debug.LogWarning($"<b>[MCPLogPrivacy]</b> | Public key unusable, personal data stays in plain text: {failure}");
            return false;
        }

        /// <summary>
        /// Marks a value as personal data so every whole-word occurrence in an upload gets encrypted.
        /// </summary>
        public static void RegisterSensitive(string value)
        {
            if (string.IsNullOrWhiteSpace(value)) return;

            value = value.Trim();
            if (value.Length < MinSensitiveLength || IgnoredValues.Contains(value)) return;

            lock (Sync)
            {
                if (SensitiveValues.Add(value)) matcher = null;
            }
        }

        /// <summary>
        /// Encrypts a single structured value, or returns it unchanged while no key is configured.
        /// </summary>
        public static string Protect(string value)
        {
            if (string.IsNullOrEmpty(value) || value == "-") return value;

            lock (Sync)
            {
                return IsActive ? TokenFor(value) : value;
            }
        }

        /// <summary>
        /// Encrypts every registered value and email address in the text; idempotent, existing tokens are never matched again.
        /// </summary>
        public static string Redact(string text)
        {
            if (string.IsNullOrEmpty(text)) return text;

            lock (Sync)
            {
                if (!IsActive) return text;

                matcher ??= BuildMatcher();
                return matcher.Replace(text, m => TokenFor(m.Value));
            }
        }

        /// <summary>
        /// Builds one whole-word matcher: emails first, then sensitive values longest first so full names win over parts of them.
        /// </summary>
        private static Regex BuildMatcher()
        {
            var alternatives = SensitiveValues
                .OrderByDescending(v => v.Length)
                .Select(Regex.Escape)
                .Prepend(EmailPattern);

            return new Regex($"(?<!{WordChar})(?:{string.Join("|", alternatives)})(?!{WordChar})",
                             RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
        }

        /// <summary>
        /// Returns [pii:BASE64URL(iv | AES-256-CBC(plain))] with iv = HMAC-SHA256(macKey, plain)[0..16].
        /// </summary>
        private static string TokenFor(string plain)
        {
            if (TokenCache.TryGetValue(plain, out string cached)) return cached;

            byte[] data = Encoding.UTF8.GetBytes(plain);
            byte[] iv;

            using (var hmac = new HMACSHA256(macKey))
                iv = hmac.ComputeHash(data).Take(16).ToArray();

            byte[] cipher;
            using (var aes = new AesCryptoServiceProvider())
            {
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.Key = encKey;
                aes.IV = iv;

                using ICryptoTransform encryptor = aes.CreateEncryptor();
                cipher = encryptor.TransformFinalBlock(data, 0, data.Length);
            }

            byte[] blob = new byte[iv.Length + cipher.Length];
            Buffer.BlockCopy(iv, 0, blob, 0, iv.Length);
            Buffer.BlockCopy(cipher, 0, blob, iv.Length, cipher.Length);

            string token = TokenPrefix + Base64Url(blob) + TokenSuffix;
            TokenCache[plain] = token;
            return token;
        }

        /// <summary>
        /// Encodes bytes as unpadded URL-safe base64.
        /// </summary>
        private static string Base64Url(byte[] data) =>
            Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        /// <summary>
        /// Returns the first 8 hex digits of SHA-256 over the modulus so the reader can pick the right private key.
        /// </summary>
        private static string KeyId(RSAParameters parameters)
        {
            using var sha = new SHA256Managed();
            byte[] hash = sha.ComputeHash(parameters.Modulus);
            return BitConverter.ToString(hash, 0, 4).Replace("-", string.Empty).ToLowerInvariant();
        }

        #region PEM parsing

        /// <summary>
        /// Reads modulus and exponent from an SPKI or PKCS#1 RSA public key PEM, since netstandard2.1 has no importer for it.
        /// </summary>
        private static RSAParameters ParsePublicKeyPem(string pem)
        {
            string base64 = Regex.Replace(pem, @"-----[^-]+-----|\s", string.Empty);
            byte[] der = Convert.FromBase64String(base64);

            int pos = 0;
            int end = ReadHeader(der, ref pos, 0x30);

            if (der[pos] == 0x30)
            {
                pos = ReadHeader(der, ref pos, 0x30);
                ReadHeader(der, ref pos, 0x03);
                pos++;
                end = ReadHeader(der, ref pos, 0x30);
            }

            byte[] modulus = ReadInteger(der, ref pos);
            byte[] exponent = ReadInteger(der, ref pos);

            if (pos > end || modulus.Length < 256) throw new FormatException("expected an RSA public key of at least 2048 bits");

            return new RSAParameters { Modulus = modulus, Exponent = exponent };
        }

        /// <summary>
        /// Reads a DER tag and length at the position and returns the end offset of its content.
        /// </summary>
        private static int ReadHeader(byte[] der, ref int pos, byte expectedTag)
        {
            if (der[pos++] != expectedTag) throw new FormatException($"unexpected DER tag at {pos - 1}");

            int length = der[pos++];
            if ((length & 0x80) != 0)
            {
                int count = length & 0x7F;
                length = 0;
                for (int i = 0; i < count; i++) length = (length << 8) | der[pos++];
            }

            return pos + length;
        }

        /// <summary>
        /// Reads a DER INTEGER as unsigned big-endian bytes without the sign padding.
        /// </summary>
        private static byte[] ReadInteger(byte[] der, ref int pos)
        {
            int end = ReadHeader(der, ref pos, 0x02);
            int start = pos;
            while (start < end - 1 && der[start] == 0) start++;

            byte[] value = new byte[end - start];
            Buffer.BlockCopy(der, start, value, 0, value.Length);
            pos = end;
            return value;
        }

        #endregion
    }
}
