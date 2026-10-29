using System.IO;
using UnityEditor;
using UnityEditor.Build;
using UnityEditor.Build.Reporting;
using UnityEngine;
using UnityEngine.SceneManagement;

namespace UnityLogsMCP.Editor
{
    public class MCPLoggerApiKeyWindow : EditorWindow
    {
        private string apiKey = ""; // The key is never stored in the scene file, so the editor reads it from ApiKeyFile and development builds get it injected into the built scene.

        [MenuItem("Tools/Unity Logs MCP/Set API Key")]
        private static void Open() => GetWindow<MCPLoggerApiKeyWindow>(true, "MCPLogger API Key").minSize = new Vector2(420, 110);

        private void OnGUI()
        {
            EditorGUILayout.HelpBox(File.Exists(MCPLogger.ApiKeyFile)
                ? $"A key is stored in {MCPLogger.ApiKeyFile}. Saving replaces it."
                : $"No key stored yet. It goes to {MCPLogger.ApiKeyFile}, which must stay out of git.", MessageType.Info);

            apiKey = EditorGUILayout.PasswordField("API Key", apiKey);

            using (new EditorGUI.DisabledScope(string.IsNullOrWhiteSpace(apiKey)))
            {
                if (GUILayout.Button("Save"))
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(MCPLogger.ApiKeyFile));
                    File.WriteAllText(MCPLogger.ApiKeyFile, apiKey.Trim());
                    Debug.Log($"MCPLogger: API key saved to {MCPLogger.ApiKeyFile}.");
                    Close();
                }
            }
        }
    }

    /// <summary>
    /// Runs on every scene of a build: development builds get the API key injected into the built copy of the scene, release builds lose the logger entirely.
    /// </summary>
    internal class MCPLoggerBuildProcessor : IProcessSceneWithReport
    {
        public int callbackOrder => 0;

        public void OnProcessScene(Scene scene, BuildReport report)
        {
            if (report == null) return;   // Play mode; the logger reads the key file itself there.

            var loggers = Object.FindObjectsByType<MCPLogger>(FindObjectsInactive.Include, FindObjectsSortMode.None);
            if (loggers.Length == 0) return;

            if ((report.summary.options & BuildOptions.Development) == 0)
            {
                foreach (var logger in loggers) Object.DestroyImmediate(logger);
                return;
            }

            string key = File.Exists(MCPLogger.ApiKeyFile) ? File.ReadAllText(MCPLogger.ApiKeyFile).Trim() : "";
            if (key.Length == 0)
                Debug.LogWarning($"MCPLogger: no API key in {MCPLogger.ApiKeyFile}, this build will not upload logs. Set one via Tools > Unity Logs MCP > Set API Key.");

            foreach (var logger in loggers)
            {
                var so = new SerializedObject(logger);
                so.FindProperty("apiKey").stringValue = key;
                so.ApplyModifiedPropertiesWithoutUndo();
            }
        }
    }
}
