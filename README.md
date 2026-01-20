# aipriv

AI-driven privilege escalation testing for authorized security testing and CTF challenges.

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt
cp .env.example .env

# Terminal 1: Start proxy
python3 proxy_relay.py

# Terminal 2: Start client (in container or target)
python3 iclient.py 172.17.0.1 65432

# Terminal 3: Configure Claude Desktop/Code with MCP server
```

## Architecture

```
Claude Desktop/Code
        |  MCP Protocol (stdio)
        v
   mcp_server.py
        |  Socket (port 65433)
        v
   proxy_relay.py
        |  Socket (port 65432)
        v
   iclient(s)  [client_1, client_2, ...]
```

**Components:**
- **proxy_relay.py** - Multi-client proxy (bridges MCP server and iclients)
- **mcp_server.py** - MCP server exposing tools to AI clients
- **iclient.py** - Executes commands on target system
- **iserver.py** - Legacy server (Gemini API only)

## MCP Configuration

### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "privilege-escalation": {
      "command": "python3",
      "args": ["/absolute/path/to/aipriv/mcp_server.py"],
      "env": {
        "PRIVESC_CLIENT_HOST": "127.0.0.1",
        "PRIVESC_CLIENT_PORT": "65433"
      }
    }
  }
}
```

### Claude Code

Add to `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "privilege-escalation": {
      "command": "python3",
      "args": ["/absolute/path/to/aipriv/mcp_server.py"],
      "env": {
        "PRIVESC_CLIENT_HOST": "127.0.0.1",
        "PRIVESC_CLIENT_PORT": "65433"
      }
    }
  }
}
```

## Available Tools

| Tool | Description |
|------|-------------|
| `connect_to_client` | Connect to proxy (host, port optional) |
| `start_session` | Start interactive shell on target |
| `execute_command` | Run shell command (command, session_id?, client_id?) |
| `reset_shell` | Reset unresponsive shell |
| `stop_session` | Stop session |
| `get_session_info` | Get connection status |
| `list_clients` | List all connected iclients |
| `set_client` | Set default target client |

## Docker Setup

```bash
# Terminal 1: Start proxy
python3 proxy_relay.py

# Terminal 2: Build and run container
docker build -t suidpath_container containers/suidpath/
docker run -it suidpath_container

# Inside container:
python3 /home/ctfuser/iclient.py 172.17.0.1 65432
```

Multiple containers connect to the same proxy and appear as `client_1`, `client_2`, etc.

## Legacy Mode (Gemini)

```bash
# Set GEMINI_API_KEY in .env
python iserver.py 8000
python3 iclient.py 127.0.0.1 8000
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Connection refused | Ensure proxy_relay.py is running first |
| No clients connected | Ensure iclient connected to proxy (port 65432) |
| MCP server not found | Check absolute path, restart Claude |
| Module 'mcp' not found | `pip install mcp` |
| Container can't connect | Use `172.17.0.1` (Docker gateway) not `127.0.0.1` |

## Security

**Authorized use only:**
- Penetration testing with permission
- CTF challenges
- Security research
- Defensive testing

## References

- [MCP Specification](https://spec.modelcontextprotocol.io/)
- [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk)
