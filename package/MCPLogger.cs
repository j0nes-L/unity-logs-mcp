using System;
using System.Collections;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using UnityEngine;
using UnityEngine.Networking;

namespace UnityLogsMCP
{
    /// <summary>
    /// Collects the Unity log of this run and uploads it to a log endpoint, personal data encrypted via <see cref="MCPLogPrivacy"/>.
    /// </summary>
    public class MCPLogger : MonoBehaviour
    {
        private const int UploadMaxAttempts = 3;            // Attempts for an upload that still has a coroutine to run in. A lost log is not worth more than this.
        private const float UploadRetryDelay = 2f;          // Seconds between those attempts.
        private const int UploadSyncTimeoutMs = 4000;       // Budget for the upload at quit. The player is waiting on it, and Android kills a process that takes too long to die.
        private const int BufferMaxChars = 1024 * 1024;     // What the log may hold. Several megabytes over headset Wi-Fi do not fit into the quit timeout, so the oldest lines go first.
        private const int MetaMaxChars = 200;               // Keeps free-text query parameters, and with them the URL, sane.

        public const string ApiKeyFile = "UserSettings/MCPLoggerApiKey.txt";  // Relative to the project root. UserSettings/ is in Unity's default .gitignore, so the key never reaches the repo.

        [SerializeField] private string endpoint = "";              // Full ingest URL, e.g. https://logs.example.com/logs
        [SerializeField, HideInInspector] private string apiKey = "";  // Stays empty in the scene file; the editor reads ApiKeyFile, development builds get it injected into the built scene.
        [SerializeField] private string apiKeyHeader = "X-API-Key"; // The header the server expects the API key in. The default is what the log MCP server expects, but a custom endpoint may want a different one.
        [SerializeField, TextArea(3, 10)] private string publicKeyPem = "";  // RSA public key of the MCP server (PEM, SPKI or PKCS#1, at least 2048 bit).
        [SerializeField] private bool uploadOnQuit = true;          // Also covers going to the background on mobile, the last moment Android reliably gives a closing app.

        public static MCPLogger Instance { get; private set; }

        private readonly StringBuilder buffer = new StringBuilder();    // The log lines collected so far. Accessed from any thread, so lock it.
        private readonly object bufferLock = new object();              // Lock for the buffer, because HandleLog is called from any thread.
        private readonly string sessionId = Guid.NewGuid().ToString("N");  // Every upload of this run carries it, so the server can keep the newest one per session.
        private string deviceId;    // Hash of the device id, so the server can group logs per device without seeing the raw id.

        private void Awake()
        {
            // A debugging tool; release builds strip it from scenes, this catches instances spawned from prefabs.
            if (!Debug.isDebugBuild || (Instance != null && Instance != this))
            {
                Destroy(this);
                return;
            }

            Instance = this;
            DontDestroyOnLoad(gameObject);
            Application.logMessageReceivedThreaded += HandleLog;

#if UNITY_EDITOR
            if (string.IsNullOrEmpty(apiKey) && File.Exists(ApiKeyFile))
                apiKey = File.ReadAllText(ApiKeyFile).Trim();
#endif

            deviceId = HashDeviceId(SystemInfo.deviceUniqueIdentifier);

            if (!MCPLogPrivacy.Configure(publicKeyPem))
                Debug.LogWarning("MCPLogger: no usable public key, personal data will be uploaded in plain text.");

            MCPLogPrivacy.RegisterSensitive(SystemInfo.deviceUniqueIdentifier);
            if (Application.isEditor || Application.platform == RuntimePlatform.WindowsPlayer || Application.platform == RuntimePlatform.OSXPlayer)
                MCPLogPrivacy.RegisterSensitive(Environment.UserName);
        }

        private void OnDestroy()
        {
            if (Instance != this) return;

            Application.logMessageReceivedThreaded -= HandleLog;
            Instance = null;
        }

        /// <summary>
        /// Stable per device but not reversible, unlike the raw id, which is personal data and encrypted in the log body.
        /// </summary>
        private static string HashDeviceId(string rawId)
        {
            using var sha = SHA256.Create();
            byte[] hash = sha.ComputeHash(Encoding.UTF8.GetBytes(rawId ?? string.Empty));
            return BitConverter.ToString(hash, 0, 8).Replace("-", string.Empty).ToLowerInvariant();
        }

        private void OnApplicationQuit()
        {
            if (uploadOnQuit && TryPrepareUpload("quit", out string url, out byte[] body))
                UploadSync(url, body, "quit");
        }

        /// <summary>
        /// Android and Quest often kill a backgrounded app without OnApplicationQuit, so pausing is where the log has to leave.
        /// </summary>
        private void OnApplicationPause(bool paused)
        {
            if (paused && uploadOnQuit && Application.isMobilePlatform && TryPrepareUpload("pause", out string url, out byte[] body))
                UploadSync(url, body, "pause");
        }

        /// <summary>
        /// Uploads the log collected so far while the app keeps running.
        /// </summary>
        public void Upload(string reason = "manual")
        {
            if (TryPrepareUpload(reason, out string url, out byte[] body))
                StartCoroutine(UploadRoutine(url, body, reason));
        }

        /// <summary>
        /// Appends one log line. Called from any thread.
        /// </summary>
        private void HandleLog(string condition, string stackTrace, LogType type)
        {
            lock (bufferLock)
            {
                buffer.Append(DateTime.UtcNow.ToString("HH:mm:ss.fff")).Append(" [").Append(type).Append("] ").AppendLine(condition);

                if (type == LogType.Exception || type == LogType.Error || type == LogType.Assert)
                    buffer.AppendLine(stackTrace);

                if (buffer.Length > BufferMaxChars)
                    buffer.Remove(0, buffer.Length - BufferMaxChars * 3 / 4);
            }
        }

        /// <summary>
        /// Snapshots the log, appends the context block, encrypts personal data and builds the ingest URL.
        /// </summary>
        private bool TryPrepareUpload(string reason, out string url, out byte[] body)
        {
            url = null;
            body = null;

            if (string.IsNullOrEmpty(endpoint) || string.IsNullOrEmpty(apiKey))
            {
                Debug.LogWarning("MCPLogger: upload skipped, endpoint or API key is not configured.");
                return false;
            }

            string text;
            lock (bufferLock) text = buffer.ToString();
            if (text.Length == 0) return false;

            body = Encoding.UTF8.GetBytes(MCPLogPrivacy.Redact(text + BuildContext()));
            url = BuildUploadUrl(reason);
            return true;
        }

        /// <summary>
        /// The part of the log Unity does not write itself, including the key the server needs to decrypt personal data.
        /// </summary>
        private string BuildContext()
        {
            var sb = new StringBuilder();

            sb.AppendLine();
            sb.AppendLine("# ================ MCPLogger context ================");
            sb.AppendLine($"# session      : {sessionId}");
            sb.AppendLine($"# device       : {SystemInfo.deviceModel}");
            sb.AppendLine($"# device id    : {deviceId}");
            sb.AppendLine($"# platform     : {Application.platform} / {SystemInfo.operatingSystem}");
            sb.AppendLine($"# app version  : {Application.version} (Unity {Application.unityVersion})");
            sb.AppendLine($"# pii key      : {MCPLogPrivacy.KeyLine}");
            sb.AppendLine("# ===================================================");

            return sb.ToString();
        }

        /// <summary>
        /// Builds the ingest URL.
        /// </summary>
        private string BuildUploadUrl(string reason)
        {
            var url = new StringBuilder($"{endpoint.TrimEnd('/')}?reason={UnityWebRequest.EscapeURL(string.IsNullOrEmpty(reason) ? "manual" : reason)}");

            AppendMeta(url, "session", sessionId);
            AppendMeta(url, "device", SystemInfo.deviceModel);
            AppendMeta(url, "device_id", deviceId);
            AppendMeta(url, "platform", $"{Application.platform} / {SystemInfo.operatingSystem}");
            AppendMeta(url, "app_version", Application.version);
            AppendMeta(url, "unity_version", Application.unityVersion);

            return url.ToString();
        }

        /// <summary>
        /// Appends one query parameter, skipping empties and trimming long values.
        /// </summary>
        private static void AppendMeta(StringBuilder url, string key, string value)
        {
            if (string.IsNullOrEmpty(value)) return;

            if (value.Length > MetaMaxChars) value = value.Substring(0, MetaMaxChars);

            url.Append('&').Append(key).Append('=').Append(UnityWebRequest.EscapeURL(value));
        }

        /// <summary>
        /// Uploads a log while the app is still running, retrying what is worth retrying.
        /// </summary>
        private IEnumerator UploadRoutine(string url, byte[] body, string reason)
        {
            for (int attempt = 1; attempt <= UploadMaxAttempts; attempt++)
            {
                long responseCode;
                string failure;

                using (UnityWebRequest req = new UnityWebRequest(url, UnityWebRequest.kHttpVerbPOST))
                {
                    req.uploadHandler = new UploadHandlerRaw(body);
                    req.downloadHandler = new DownloadHandlerBuffer();
                    req.SetRequestHeader("Content-Type", "text/plain; charset=utf-8");
                    req.SetRequestHeader(apiKeyHeader, apiKey);

                    yield return req.SendWebRequest();

                    if (req.result == UnityWebRequest.Result.Success)
                    {
                        Debug.Log($"MCPLogger: log uploaded (reason={reason}, {body.Length / 1024} KB, {req.responseCode}).");
                        yield break;
                    }

                    responseCode = req.responseCode;
                    failure = $"{req.responseCode} {req.error} - {req.downloadHandler.text}";
                }

                bool worthRetrying = responseCode == 0 || responseCode >= 500;

                if (!worthRetrying || attempt == UploadMaxAttempts)
                {
                    Debug.LogWarning($"MCPLogger: log upload failed (reason={reason}): {failure}.");
                    yield break;
                }

                yield return new WaitForSecondsRealtime(UploadRetryDelay);
            }
        }

        /// <summary>
        /// Uploads a log from a shutdown path, where no coroutine will run anymore.
        /// </summary>
        private void UploadSync(string url, byte[] body, string reason)
        {
            try
            {
                var request = (HttpWebRequest)WebRequest.Create(url);
                request.Method = "POST";
                request.ContentType = "text/plain; charset=utf-8";
                request.ContentLength = body.Length;
                request.Timeout = UploadSyncTimeoutMs;
                request.ReadWriteTimeout = UploadSyncTimeoutMs;
                request.Headers[apiKeyHeader] = apiKey;

                using (Stream stream = request.GetRequestStream())
                    stream.Write(body, 0, body.Length);

                using var response = (HttpWebResponse)request.GetResponse();
                Debug.Log($"MCPLogger: log uploaded on shutdown (reason={reason}, {body.Length / 1024} KB, {(int)response.StatusCode}).");
            }
            catch (WebException ex)
            {
                Debug.LogWarning($"MCPLogger: log upload on shutdown failed (reason={reason}): {ex.Message} - {ReadErrorBody(ex)}");
            }
            catch (Exception ex)
            {
                Debug.LogWarning($"MCPLogger: log upload on shutdown failed (reason={reason}): {ex.Message}");
            }
        }

        /// <summary>
        /// Pulls the response body out of a failed HttpWebRequest, which is where the server explains itself.
        /// </summary>
        private static string ReadErrorBody(WebException ex)
        {
            try
            {
                if (ex.Response == null) return "no response body";

                using var stream = ex.Response.GetResponseStream();
                if (stream == null) return "no response body";

                using var reader = new StreamReader(stream);
                string body = reader.ReadToEnd();

                return string.IsNullOrEmpty(body) ? "empty response body" : body.Substring(0, Math.Min(body.Length, 500));
            }
            catch
            {
                return "response body unreadable";
            }
        }
    }
}
