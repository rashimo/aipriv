#!/usr/bin/env python3
"""
MCP Server for Privilege Escalation Testing

This MCP server exposes command execution capabilities for authorized
security testing and CTF scenarios. It communicates with a client
running on a target system via sockets.
"""

import asyncio
import json
import logging
import os
import socket
import struct
from typing import Any, Dict, Optional, Sequence

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    Resource,
    Tool,
    TextContent,
    ImageContent,
    EmbeddedResource,
    Prompt,
    PromptMessage,
    GetPromptResult,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("mcp-privesc-server")

# Constants
SHELL_RESET_COMMAND = "INITIATE_NEW_SHELL_SESSION"
DEFAULT_TIMEOUT = 10
DEFAULT_MCP_PORT = 65433  # Connect to proxy, not iclient directly


class ClientConnectionManager:
    """Manages connections to the privilege escalation client."""

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.connection: Optional[socket.socket] = None
        self.interactive_session_id: Optional[str] = None
        self.session_active = False
        self.current_client_id: Optional[str] = None  # For proxy routing

    def connect(self) -> bool:
        """Establish connection to the client."""
        try:
            if self.connection:
                self.disconnect()

            self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.connection.settimeout(30)
            self.connection.connect((self.host, self.port))
            logger.info(f"Connected to client at {self.host}:{self.port}")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to client: {e}")
            return False

    def disconnect(self):
        """Close the connection to the client."""
        if self.connection:
            try:
                self.connection.close()
            except:
                pass
            self.connection = None
        self.session_active = False
        self.interactive_session_id = None
        logger.info("Disconnected from client")

    def send_message(self, msg: str) -> bool:
        """Send a message to the client using length-prefix protocol."""
        if not self.connection:
            logger.error("Cannot send message: not connected")
            return False

        try:
            msg_bytes = msg.encode('utf-8')
            len_prefix = struct.pack('>I', len(msg_bytes))
            self.connection.sendall(len_prefix + msg_bytes)
            return True
        except Exception as e:
            logger.error(f"Error sending message: {e}")
            return False

    def recv_message(self) -> Optional[str]:
        """Receive a message from the client using length-prefix protocol."""
        if not self.connection:
            logger.error("Cannot receive message: not connected")
            return None

        try:
            raw_msglen = self.connection.recv(4)
            if not raw_msglen:
                return None

            msglen = struct.unpack('>I', raw_msglen)[0]
            data = bytearray()

            while len(data) < msglen:
                packet = self.connection.recv(msglen - len(data))
                if not packet:
                    return None
                data.extend(packet)

            return data.decode('utf-8')
        except Exception as e:
            logger.error(f"Error receiving message: {e}")
            return None

    def start_interactive_session(self, client_id: Optional[str] = None) -> Dict[str, Any]:
        """Start an interactive shell session on the client."""
        if not self.connection:
            return {"status": "error", "result": "Not connected to proxy"}

        try:
            # Use provided client_id or current default
            target_client = client_id or self.current_client_id

            payload_dict = {"action": "start_interactive"}
            if target_client:
                payload_dict["client_id"] = target_client

            payload = json.dumps(payload_dict)
            if not self.send_message(payload):
                return {"status": "error", "result": "Failed to send start command"}

            response_str = self.recv_message()
            if not response_str:
                return {"status": "error", "result": "No response from client"}

            response = json.loads(response_str)

            if response.get("status") == "success":
                self.interactive_session_id = response.get("session_id")
                self.session_active = True
                logger.info(f"Started interactive session: {self.interactive_session_id}")

            return response

        except Exception as e:
            logger.error(f"Error starting interactive session: {e}")
            return {"status": "error", "result": str(e)}

    def execute_command(self, command: str, session_id: Optional[str] = None, client_id: Optional[str] = None) -> Dict[str, Any]:
        """Execute a command on the client."""
        if not self.connection:
            return {"status": "error", "result": "Not connected to proxy"}

        try:
            # Use provided client_id or current default
            target_client = client_id or self.current_client_id

            # Use interactive session if available
            if session_id or self.interactive_session_id:
                sid = session_id or self.interactive_session_id
                payload_dict = {
                    "action": "run_interactive",
                    "session_id": sid,
                    "command": command
                }
            else:
                # Fallback to simple execution
                payload_dict = {
                    "action": "execute",
                    "command": command
                }

            # Add client_id for proxy routing
            if target_client:
                payload_dict["client_id"] = target_client

            payload = json.dumps(payload_dict)

            if not self.send_message(payload):
                return {"status": "error", "result": "Failed to send command"}

            response_str = self.recv_message()
            if not response_str:
                return {"status": "error", "result": "No response from client"}

            response = json.loads(response_str)
            logger.info(f"Command executed: {command[:50]}... | Status: {response.get('status')}")

            return response

        except Exception as e:
            logger.error(f"Error executing command: {e}")
            return {"status": "error", "result": str(e)}

    def stop_session(self, session_id: Optional[str] = None, client_id: Optional[str] = None) -> Dict[str, Any]:
        """Stop an interactive session."""
        if not self.connection:
            return {"status": "error", "result": "Not connected to proxy"}

        try:
            sid = session_id or self.interactive_session_id
            if not sid:
                return {"status": "error", "result": "No active session"}

            # Use provided client_id or current default
            target_client = client_id or self.current_client_id

            payload_dict = {
                "action": "stop_interactive",
                "session_id": sid
            }
            if target_client:
                payload_dict["client_id"] = target_client

            payload = json.dumps(payload_dict)

            if not self.send_message(payload):
                return {"status": "error", "result": "Failed to send stop command"}

            response_str = self.recv_message()
            if not response_str:
                return {"status": "error", "result": "No response from client"}

            response = json.loads(response_str)

            if response.get("status") == "success":
                if sid == self.interactive_session_id:
                    self.interactive_session_id = None
                    self.session_active = False
                logger.info(f"Stopped session: {sid}")

            return response

        except Exception as e:
            logger.error(f"Error stopping session: {e}")
            return {"status": "error", "result": str(e)}

    def reset_shell(self) -> Dict[str, Any]:
        """Reset the shell by stopping the current session and starting a new one."""
        logger.info("Resetting shell session...")

        # Stop current session
        if self.interactive_session_id:
            stop_result = self.stop_session()
            if stop_result.get("status") != "success":
                logger.warning(f"Failed to cleanly stop session: {stop_result}")

        # Start new session
        return self.start_interactive_session()

    def list_clients(self) -> Dict[str, Any]:
        """List all connected iclients (via proxy)."""
        if not self.connection:
            return {"status": "error", "result": "Not connected to proxy"}

        try:
            payload = json.dumps({"action": "list_clients"})
            if not self.send_message(payload):
                return {"status": "error", "result": "Failed to send list_clients command"}

            response_str = self.recv_message()
            if not response_str:
                return {"status": "error", "result": "No response from proxy"}

            response = json.loads(response_str)
            logger.info(f"Listed clients: {response}")
            return response

        except Exception as e:
            logger.error(f"Error listing clients: {e}")
            return {"status": "error", "result": str(e)}

    def set_client(self, client_id: str) -> Dict[str, Any]:
        """Set the current client for subsequent commands."""
        self.current_client_id = client_id
        logger.info(f"Set current client to: {client_id}")
        return {"status": "success", "result": f"Client set to {client_id}"}


# Initialize the MCP server
app = Server("privilege-escalation-server")

# Global connection manager (will be initialized from environment)
client_manager: Optional[ClientConnectionManager] = None


@app.list_resources()
async def list_resources() -> list[Resource]:
    """List available resources."""
    resources = [
        Resource(
            uri="privesc://prompt",
            name="Privilege Escalation Prompt",
            mimeType="text/plain",
            description="System prompt for privilege escalation methodology"
        ),
        Resource(
            uri="privesc://session/status",
            name="Session Status",
            mimeType="application/json",
            description="Current session status and connection information"
        )
    ]

    return resources


@app.read_resource()
async def read_resource(uri: str) -> str:
    """Read a resource by URI."""

    if uri == "privesc://prompt":
        # Load the prompt from file
        try:
            prompt_path = os.path.join(os.path.dirname(__file__), "prompt.txt")
            with open(prompt_path, 'r') as f:
                prompt_content = f.read()
                # Replace the placeholder with actual command
                prompt_content = prompt_content.format(SHELL_RESET_COMMAND=SHELL_RESET_COMMAND)
                return prompt_content
        except FileNotFoundError:
            return "Error: prompt.txt not found. Please ensure it exists in the same directory."
        except Exception as e:
            return f"Error reading prompt: {str(e)}"

    elif uri == "privesc://session/status":
        # Return current session status
        if not client_manager:
            status = {
                "connected": False,
                "error": "Client manager not initialized"
            }
        else:
            status = {
                "connected": client_manager.connection is not None,
                "session_active": client_manager.session_active,
                "session_id": client_manager.interactive_session_id,
                "client_host": client_manager.host,
                "client_port": client_manager.port
            }
        return json.dumps(status, indent=2)

    else:
        raise ValueError(f"Unknown resource: {uri}")


@app.list_prompts()
async def list_prompts() -> list[Prompt]:
    """List available prompts."""
    return [
        Prompt(
            name="privilege_escalation",
            description="Privilege escalation testing prompt with methodology and rules",
            arguments=[]
        )
    ]


@app.get_prompt()
async def get_prompt(name: str, arguments: dict[str, str] | None = None) -> GetPromptResult:
    """Get a specific prompt."""

    if name == "privilege_escalation":
        # Load the prompt content
        try:
            prompt_path = os.path.join(os.path.dirname(__file__), "prompt.txt")
            with open(prompt_path, 'r') as f:
                prompt_content = f.read()
                prompt_content = prompt_content.format(SHELL_RESET_COMMAND=SHELL_RESET_COMMAND)
        except Exception as e:
            prompt_content = f"Error loading prompt: {str(e)}"

        return GetPromptResult(
            description="Privilege escalation methodology and rules for security testing",
            messages=[
                PromptMessage(
                    role="user",
                    content=TextContent(
                        type="text",
                        text=prompt_content
                    )
                )
            ]
        )

    raise ValueError(f"Unknown prompt: {name}")


@app.list_tools()
async def list_tools() -> list[Tool]:
    """List available tools."""
    return [
        Tool(
            name="connect_to_client",
            description="Connect to the privilege escalation client running on the target system",
            inputSchema={
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Client host address (default from environment)"
                    },
                    "port": {
                        "type": "integer",
                        "description": "Client port (default from environment)"
                    }
                }
            }
        ),
        Tool(
            name="start_session",
            description="Start an interactive shell session on the target system",
            inputSchema={
                "type": "object",
                "properties": {}
            }
        ),
        Tool(
            name="execute_command",
            description="Execute a shell command on the target system. Returns command output.",
            inputSchema={
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "The shell command to execute"
                    },
                    "session_id": {
                        "type": "string",
                        "description": "Optional session ID (uses active session if not specified)"
                    },
                    "client_id": {
                        "type": "string",
                        "description": "Optional client ID to target (uses default client if not specified)"
                    }
                },
                "required": ["command"]
            }
        ),
        Tool(
            name="reset_shell",
            description="Reset the shell session if it becomes unresponsive or broken. Stops current session and starts a fresh one.",
            inputSchema={
                "type": "object",
                "properties": {}
            }
        ),
        Tool(
            name="stop_session",
            description="Stop an active interactive session",
            inputSchema={
                "type": "object",
                "properties": {
                    "session_id": {
                        "type": "string",
                        "description": "Session ID to stop (uses active session if not specified)"
                    }
                }
            }
        ),
        Tool(
            name="get_session_info",
            description="Get information about the current session and connection status",
            inputSchema={
                "type": "object",
                "properties": {}
            }
        ),
        Tool(
            name="list_clients",
            description="List all connected iclients (when using proxy). Returns client IDs and addresses.",
            inputSchema={
                "type": "object",
                "properties": {}
            }
        ),
        Tool(
            name="set_client",
            description="Set the target client for subsequent commands (when using proxy with multiple clients)",
            inputSchema={
                "type": "object",
                "properties": {
                    "client_id": {
                        "type": "string",
                        "description": "The client ID to target (e.g., 'client_1')"
                    }
                },
                "required": ["client_id"]
            }
        )
    ]


@app.call_tool()
async def call_tool(name: str, arguments: Any) -> Sequence[TextContent | ImageContent | EmbeddedResource]:
    """Handle tool calls."""
    global client_manager

    try:
        if name == "connect_to_client":
            # Get connection parameters (default to proxy port 65433)
            host = arguments.get("host") or os.getenv("PRIVESC_CLIENT_HOST", "127.0.0.1")
            port = arguments.get("port") or int(os.getenv("PRIVESC_CLIENT_PORT", str(DEFAULT_MCP_PORT)))

            # Initialize or update connection manager
            client_manager = ClientConnectionManager(host, port)

            # Attempt connection
            success = client_manager.connect()

            if success:
                result = {
                    "status": "success",
                    "message": f"Connected to client at {host}:{port}",
                    "next_step": "Use start_session to begin an interactive shell"
                }
            else:
                result = {
                    "status": "error",
                    "message": "Failed to connect to client. Ensure the client is running."
                }

            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        elif name == "start_session":
            if not client_manager or not client_manager.connection:
                return [TextContent(
                    type="text",
                    text=json.dumps({
                        "status": "error",
                        "message": "Not connected to client. Use connect_to_client first."
                    }, indent=2)
                )]

            result = client_manager.start_interactive_session()
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        elif name == "execute_command":
            if not client_manager or not client_manager.connection:
                return [TextContent(
                    type="text",
                    text=json.dumps({
                        "status": "error",
                        "message": "Not connected to proxy. Use connect_to_client first."
                    }, indent=2)
                )]

            command = arguments.get("command")
            if not command:
                return [TextContent(
                    type="text",
                    text=json.dumps({
                        "status": "error",
                        "message": "Command is required"
                    }, indent=2)
                )]

            session_id = arguments.get("session_id")
            client_id = arguments.get("client_id")
            result = client_manager.execute_command(command, session_id, client_id)

            # Check for root achievement
            if command.strip() == "whoami" and result.get("status") == "success":
                output = result.get("result", "")
                if "root" in output.strip().lower():
                    result["achievement"] = "ROOT_ACHIEVED"
                    result["message"] = "Congratulations! Root privileges obtained!"

            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        elif name == "reset_shell":
            if not client_manager or not client_manager.connection:
                return [TextContent(
                    type="text",
                    text=json.dumps({
                        "status": "error",
                        "message": "Not connected to client. Use connect_to_client first."
                    }, indent=2)
                )]

            result = client_manager.reset_shell()
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        elif name == "stop_session":
            if not client_manager or not client_manager.connection:
                return [TextContent(
                    type="text",
                    text=json.dumps({
                        "status": "error",
                        "message": "Not connected to client"
                    }, indent=2)
                )]

            session_id = arguments.get("session_id")
            result = client_manager.stop_session(session_id)
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        elif name == "get_session_info":
            if not client_manager:
                info = {
                    "status": "not_initialized",
                    "message": "Connection manager not initialized"
                }
            else:
                info = {
                    "connected": client_manager.connection is not None,
                    "session_active": client_manager.session_active,
                    "session_id": client_manager.interactive_session_id,
                    "current_client_id": client_manager.current_client_id,
                    "client_host": client_manager.host,
                    "client_port": client_manager.port
                }

            return [TextContent(type="text", text=json.dumps(info, indent=2))]

        elif name == "list_clients":
            if not client_manager or not client_manager.connection:
                return [TextContent(
                    type="text",
                    text=json.dumps({
                        "status": "error",
                        "message": "Not connected to proxy. Use connect_to_client first."
                    }, indent=2)
                )]

            result = client_manager.list_clients()
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        elif name == "set_client":
            if not client_manager:
                return [TextContent(
                    type="text",
                    text=json.dumps({
                        "status": "error",
                        "message": "Connection manager not initialized. Use connect_to_client first."
                    }, indent=2)
                )]

            client_id = arguments.get("client_id")
            if not client_id:
                return [TextContent(
                    type="text",
                    text=json.dumps({
                        "status": "error",
                        "message": "client_id is required"
                    }, indent=2)
                )]

            result = client_manager.set_client(client_id)
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        else:
            return [TextContent(
                type="text",
                text=json.dumps({
                    "status": "error",
                    "message": f"Unknown tool: {name}"
                }, indent=2)
            )]

    except Exception as e:
        logger.error(f"Error in tool {name}: {e}", exc_info=True)
        return [TextContent(
            type="text",
            text=json.dumps({
                "status": "error",
                "message": f"Tool execution error: {str(e)}"
            }, indent=2)
        )]


async def main():
    """Main entry point for the MCP server."""
    logger.info("Starting MCP Privilege Escalation Server")

    # Log configuration
    host = os.getenv("PRIVESC_CLIENT_HOST", "127.0.0.1")
    port = os.getenv("PRIVESC_CLIENT_PORT", str(DEFAULT_MCP_PORT))
    logger.info(f"Default proxy target: {host}:{port}")
    logger.info("Use connect_to_client tool to connect to proxy")
    logger.info("Use list_clients tool to see connected iclients")

    # Run the server using stdio transport
    async with stdio_server() as (read_stream, write_stream):
        await app.run(
            read_stream,
            write_stream,
            app.create_initialization_options()
        )


if __name__ == "__main__":
    asyncio.run(main())
