# Unity Logs MCP

Uploads Unity Editor and development-build logs to your own server and makes them readable for an AI agent like Claude Code via MCP.
Personal data (names, emails, device ids, ...) is encrypted in the client and only decrypted where the private key lives.

```
Unity (MCPLogger) ──[pii:…]──► POST /logs ──► api container ──► docker volume "logs"
  encrypts with the                          no private key,        stored as uploaded
  public key                                 stores tokens               │
                                                                         ▼
                             mcp-stdio (via SSH, no network) ◄── secrets/log-private.pem
                             decrypts while reading → plain text for Claude
```

## Server

On a Linux server with Docker:

```sh
curl -fsSL https://raw.githubusercontent.com/j0nes-L/unity-logs-mcp/main/setup.sh | bash
```

It asks for the connection name, an optional domain (HTTPS via Caddy) and how long logs are kept (7 days, 30 days, unlimited),
then starts the containers and prints everything Unity and Claude Code need. Running it again updates the server and keeps all keys and logs.

## Unity

Package Manager → Add package from git URL:

```
https://github.com/j0nes-L/unity-logs-mcp.git?path=/package
```

Add the `MCPLogger` component to a GameObject in your first scene, fill in the endpoint and the public key from the setup output,
and store the Unity access key via **Tools → Unity Logs MCP → Set Unity Access Key** (kept in `UserSettings/`, never in the scene).
Only the editor and development builds upload; release builds strip the logger.

## Claude Code

Run one of the two `claude mcp add` commands the setup prints:

- **SSH (plain text):** starts the stdio MCP on the server next to the private key. Needs SSH key login and a user in the docker group.
- **HTTP (tokens only):** the remote `/mcp` endpoint with the MCP token. Personal data stays `[pii:…]`.

Tools: `list_logs`, `read_log`, `search_logs`, `log_stats`.

## Test

```sh
dotnet run --project tests/PrivacyRoundTrip
```

Encrypts with the Unity client's `MCPLogPrivacy.cs` and decrypts with the server's `LogPrivacy.cs`.
