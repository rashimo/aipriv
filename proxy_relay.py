#!/usr/bin/env python3
"""
Proxy Relay for MCP Server <-> iclient Communication

This proxy bridges the architecture gap between:
- MCP server (which connects as a client)
- iclient (which also connects as a client)

The proxy listens on two ports:
- Port 65432: For iclients to connect to
- Port 65433: For MCP server to connect to

Messages are routed between MCP server and specific iclients using client_id.
"""

import socket
import struct
import json
import logging
import threading
import select
import sys
from typing import Dict, Optional, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("proxy-relay")


class ProxyRelay:
    """
    Multi-client proxy relay for MCP server and iclients.

    Listens for iclients on one port and MCP server on another,
    routing messages between them based on client_id.
    """

    def __init__(self, client_port: int = 65432, mcp_port: int = 65433):
        self.client_port = client_port
        self.mcp_port = mcp_port

        # Client management
        self.clients: Dict[str, dict] = {}  # client_id -> {socket, addr, lock}
        self.client_counter = 0
        self.clients_lock = threading.Lock()

        # MCP connection
        self.mcp_connection: Optional[socket.socket] = None
        self.mcp_addr = None
        self.mcp_lock = threading.Lock()

        # Server sockets
        self.client_server: Optional[socket.socket] = None
        self.mcp_server: Optional[socket.socket] = None

        # Control flag
        self.running = False

    def send_message(self, sock: socket.socket, msg: str) -> bool:
        """Send a length-prefixed message over a socket."""
        try:
            msg_bytes = msg.encode('utf-8')
            len_prefix = struct.pack('>I', len(msg_bytes))
            sock.sendall(len_prefix + msg_bytes)
            return True
        except Exception as e:
            logger.error(f"Error sending message: {e}")
            return False

    def recv_message(self, sock: socket.socket, timeout: float = 30.0) -> Optional[str]:
        """Receive a length-prefixed message from a socket."""
        try:
            sock.settimeout(timeout)
            raw_msglen = sock.recv(4)
            if not raw_msglen:
                return None

            msglen = struct.unpack('>I', raw_msglen)[0]
            data = bytearray()

            while len(data) < msglen:
                packet = sock.recv(msglen - len(data))
                if not packet:
                    return None
                data.extend(packet)

            return data.decode('utf-8')
        except socket.timeout:
            return None
        except Exception as e:
            logger.error(f"Error receiving message: {e}")
            return None

    def register_client(self, sock: socket.socket, addr: tuple) -> str:
        """Register a new iclient and return its client_id."""
        with self.clients_lock:
            self.client_counter += 1
            client_id = f"client_{self.client_counter}"
            self.clients[client_id] = {
                'socket': sock,
                'addr': addr,
                'lock': threading.Lock()
            }
            logger.info(f"Registered new client: {client_id} from {addr}")

            # Notify MCP server if connected
            self._notify_mcp_client_event("connected", client_id, addr)

            return client_id

    def unregister_client(self, client_id: str):
        """Remove a client from the registry."""
        with self.clients_lock:
            if client_id in self.clients:
                client_info = self.clients.pop(client_id)
                try:
                    client_info['socket'].close()
                except:
                    pass
                logger.info(f"Unregistered client: {client_id}")

                # Notify MCP server
                self._notify_mcp_client_event("disconnected", client_id, client_info['addr'])

    def _notify_mcp_client_event(self, event: str, client_id: str, addr: tuple):
        """Notify MCP server of client connect/disconnect events."""
        if not self.mcp_connection:
            return

        notification = json.dumps({
            "type": "client_event",
            "event": event,
            "client_id": client_id,
            "addr": f"{addr[0]}:{addr[1]}"
        })

        with self.mcp_lock:
            try:
                self.send_message(self.mcp_connection, notification)
            except:
                pass

    def get_client_list(self) -> list:
        """Get list of connected clients."""
        with self.clients_lock:
            return [
                {
                    "client_id": cid,
                    "addr": f"{info['addr'][0]}:{info['addr'][1]}"
                }
                for cid, info in self.clients.items()
            ]

    def handle_client_connection(self, client_sock: socket.socket, addr: tuple):
        """Handle a connected iclient."""
        client_id = self.register_client(client_sock, addr)

        try:
            while self.running:
                # Wait for message from iclient
                message = self.recv_message(client_sock, timeout=60.0)
                if message is None:
                    # Check if it's just a timeout (no data) vs actual disconnect
                    try:
                        client_sock.send(b'')  # Test if socket is still alive
                        continue  # Just a timeout, keep waiting
                    except:
                        logger.info(f"Client {client_id} disconnected")
                        break

                logger.debug(f"Received from {client_id}: {message[:100]}...")

                # Add client_id to the response and forward to MCP
                try:
                    response_data = json.loads(message)
                    response_data['client_id'] = client_id

                    with self.mcp_lock:
                        if self.mcp_connection:
                            self.send_message(self.mcp_connection, json.dumps(response_data))
                        else:
                            logger.warning(f"No MCP connection to forward response from {client_id}")
                except json.JSONDecodeError:
                    # Forward raw message with client_id wrapper
                    wrapper = {"client_id": client_id, "raw_response": message}
                    with self.mcp_lock:
                        if self.mcp_connection:
                            self.send_message(self.mcp_connection, json.dumps(wrapper))

        except Exception as e:
            logger.error(f"Error handling client {client_id}: {e}")
        finally:
            self.unregister_client(client_id)

    def handle_mcp_connection(self, mcp_sock: socket.socket, addr: tuple):
        """Handle the MCP server connection."""
        with self.mcp_lock:
            # Close existing MCP connection if any
            if self.mcp_connection:
                try:
                    self.mcp_connection.close()
                except:
                    pass
            self.mcp_connection = mcp_sock
            self.mcp_addr = addr

        logger.info(f"MCP server connected from {addr}")

        try:
            while self.running:
                # Wait for message from MCP server
                message = self.recv_message(mcp_sock, timeout=60.0)
                if message is None:
                    # Check if it's just a timeout (no data) vs disconnect
                    try:
                        mcp_sock.send(b'')  # Test if socket is still alive
                        continue  # Just a timeout, keep waiting
                    except:
                        logger.info("MCP server disconnected")
                        break

                logger.debug(f"Received from MCP: {message[:100]}...")

                try:
                    data = json.loads(message)

                    # Handle internal proxy commands
                    if data.get("action") == "list_clients":
                        response = {
                            "status": "success",
                            "clients": self.get_client_list()
                        }
                        self.send_message(mcp_sock, json.dumps(response))
                        continue

                    # Route to specific client
                    client_id = data.get("client_id")

                    # If no client_id specified, use first available client
                    if not client_id:
                        with self.clients_lock:
                            if self.clients:
                                client_id = next(iter(self.clients.keys()))
                            else:
                                error_response = {
                                    "status": "error",
                                    "result": "No clients connected"
                                }
                                self.send_message(mcp_sock, json.dumps(error_response))
                                continue

                    # Get client socket
                    with self.clients_lock:
                        if client_id not in self.clients:
                            error_response = {
                                "status": "error",
                                "result": f"Client {client_id} not found",
                                "available_clients": list(self.clients.keys())
                            }
                            self.send_message(mcp_sock, json.dumps(error_response))
                            continue

                        client_info = self.clients[client_id]

                    # Remove client_id before forwarding to iclient (it doesn't expect it)
                    forward_data = {k: v for k, v in data.items() if k != 'client_id'}

                    # Forward to iclient
                    with client_info['lock']:
                        success = self.send_message(client_info['socket'], json.dumps(forward_data))
                        if not success:
                            error_response = {
                                "status": "error",
                                "result": f"Failed to send to client {client_id}"
                            }
                            self.send_message(mcp_sock, json.dumps(error_response))

                except json.JSONDecodeError as e:
                    logger.error(f"Invalid JSON from MCP: {e}")
                    error_response = {"status": "error", "result": f"Invalid JSON: {e}"}
                    self.send_message(mcp_sock, json.dumps(error_response))

        except Exception as e:
            logger.error(f"Error handling MCP connection: {e}")
        finally:
            with self.mcp_lock:
                self.mcp_connection = None
                self.mcp_addr = None
            logger.info("MCP connection handler ended")

    def accept_clients(self):
        """Accept loop for iclient connections."""
        while self.running:
            try:
                readable, _, _ = select.select([self.client_server], [], [], 1.0)
                if readable:
                    client_sock, addr = self.client_server.accept()
                    logger.info(f"New iclient connection from {addr}")

                    # Handle each client in a separate thread
                    thread = threading.Thread(
                        target=self.handle_client_connection,
                        args=(client_sock, addr),
                        daemon=True
                    )
                    thread.start()
            except Exception as e:
                if self.running:
                    logger.error(f"Error accepting client: {e}")

    def accept_mcp(self):
        """Accept loop for MCP server connection."""
        while self.running:
            try:
                readable, _, _ = select.select([self.mcp_server], [], [], 1.0)
                if readable:
                    mcp_sock, addr = self.mcp_server.accept()
                    logger.info(f"New MCP connection from {addr}")

                    # Handle MCP in a separate thread
                    thread = threading.Thread(
                        target=self.handle_mcp_connection,
                        args=(mcp_sock, addr),
                        daemon=True
                    )
                    thread.start()
            except Exception as e:
                if self.running:
                    logger.error(f"Error accepting MCP: {e}")

    def start(self):
        """Start the proxy relay."""
        self.running = True

        # Create server socket for iclients
        self.client_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.client_server.bind(('0.0.0.0', self.client_port))
        self.client_server.listen(5)
        logger.info(f"Listening for iclients on port {self.client_port}")

        # Create server socket for MCP
        self.mcp_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.mcp_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.mcp_server.bind(('0.0.0.0', self.mcp_port))
        self.mcp_server.listen(1)
        logger.info(f"Listening for MCP server on port {self.mcp_port}")

        # Start accept threads
        client_thread = threading.Thread(target=self.accept_clients, daemon=True)
        mcp_thread = threading.Thread(target=self.accept_mcp, daemon=True)

        client_thread.start()
        mcp_thread.start()

        logger.info("Proxy relay started. Press Ctrl+C to stop.")

        try:
            while self.running:
                # Print status periodically
                threading.Event().wait(10)
                with self.clients_lock:
                    client_count = len(self.clients)
                mcp_status = "connected" if self.mcp_connection else "not connected"
                logger.info(f"Status: {client_count} iclient(s), MCP {mcp_status}")
        except KeyboardInterrupt:
            logger.info("Shutting down...")
            self.stop()

    def stop(self):
        """Stop the proxy relay."""
        self.running = False

        # Close all client connections
        with self.clients_lock:
            for client_id, client_info in list(self.clients.items()):
                try:
                    client_info['socket'].close()
                except:
                    pass
            self.clients.clear()

        # Close MCP connection
        with self.mcp_lock:
            if self.mcp_connection:
                try:
                    self.mcp_connection.close()
                except:
                    pass
                self.mcp_connection = None

        # Close server sockets
        if self.client_server:
            try:
                self.client_server.close()
            except:
                pass

        if self.mcp_server:
            try:
                self.mcp_server.close()
            except:
                pass

        logger.info("Proxy relay stopped")


def main():
    """Main entry point."""
    client_port = 65432
    mcp_port = 65433

    # Parse command line arguments
    if len(sys.argv) >= 2:
        try:
            client_port = int(sys.argv[1])
        except ValueError:
            print(f"Error: Invalid client port '{sys.argv[1]}'")
            sys.exit(1)

    if len(sys.argv) >= 3:
        try:
            mcp_port = int(sys.argv[2])
        except ValueError:
            print(f"Error: Invalid MCP port '{sys.argv[2]}'")
            sys.exit(1)

    if len(sys.argv) > 3:
        print("Usage: python3 proxy_relay.py [client_port] [mcp_port]")
        print(f"  client_port: Port for iclients to connect (default: 65432)")
        print(f"  mcp_port: Port for MCP server to connect (default: 65433)")
        sys.exit(1)

    print(f"Starting proxy relay...")
    print(f"  iclients connect to: 0.0.0.0:{client_port}")
    print(f"  MCP server connects to: 0.0.0.0:{mcp_port}")
    print()

    proxy = ProxyRelay(client_port=client_port, mcp_port=mcp_port)
    proxy.start()


if __name__ == "__main__":
    main()
