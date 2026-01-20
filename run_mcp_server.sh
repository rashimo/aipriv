#!/bin/bash
# Launcher script for MCP Privilege Escalation Server

# Load environment variables if .env exists
if [ -f .env ]; then
    export $(cat .env | grep -v '^#' | xargs)
fi

# Set defaults if not specified
export PRIVESC_CLIENT_HOST=${PRIVESC_CLIENT_HOST:-127.0.0.1}
export PRIVESC_CLIENT_PORT=${PRIVESC_CLIENT_PORT:-65433}

echo "Starting MCP Privilege Escalation Server"
echo "Target client: $PRIVESC_CLIENT_HOST:$PRIVESC_CLIENT_PORT"
echo ""

# Run the MCP server
python3 mcp_server.py
