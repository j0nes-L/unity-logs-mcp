using System.IO;
using UnityEditor;
using UnityEditor.Build;
using UnityEditor.Build.Reporting;
using UnityEngine;
using UnityEngine.SceneManagement;

namespace UnityLogsMCP.Editor
{
    public class MCPLoggerAccessKeyWindow : EditorWindow
    {
        private string accessKey = ""; // The key is never stored in the scene file, so the editor reads it from AccessKeyFile and development builds get it injected into the built scene.

        [MenuItem("Tools/Unity Logs MCP/Set Unity Access Key")]
        private static void Open() => GetWindow<MCPLoggerAccessKeyWindow>(true, "MCPLogger Unity Access Key").minSize = new Vector2(420, 110);

        private void OnGUI()
        {
            EditorGUILayout.HelpBox(File.Exists(MCPLogger.AccessKeyFile)
                ? $"A key is stored in {MCPLogger.AccessKeyFile}. Saving replaces it."
                : $"No key stored yet. It goes to {MCPLogger.AccessKeyFile}, which must stay out of git.", MessageType.Info);

            accessKey = EditorGUILayout.PasswordField("Unity Access Key", accessKey);

            using (new EditorGUI.DisabledScope(string.IsNullOrWhiteSpace(accessKey)))
            {
                if (GUILayout.Button("Save"))
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(MCPLogger.AccessKeyFile));
                    File.WriteAllText(MCPLogger.AccessKeyFile, accessKey.Trim());
                    Debug.Log($"MCPLogger: Unity access key saved to {MCPLogger.AccessKeyFile}.");
                    Close();
                }
            }
        }
    }

    /// <summary>
    /// Runs on every scene of a build: development builds get the Unity access key injected into the built copy of the scene, release builds lose the logger entirely.
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

            string key = File.Exists(MCPLogger.AccessKeyFile) ? File.ReadAllText(MCPLogger.AccessKeyFile).Trim() : "";
            if (key.Length == 0)
                Debug.LogWarning($"MCPLogger: no Unity access key in {MCPLogger.AccessKeyFile}, this build will not upload logs. Set one via Tools > Unity Logs MCP > Set Unity Access Key.");

            foreach (var logger in loggers)
            {
                var so = new SerializedObject(logger);
                so.FindProperty("accessKey").stringValue = key;
                so.ApplyModifiedPropertiesWithoutUndo();
            }
        }
    }
}
