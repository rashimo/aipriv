import socket
import subprocess
import struct
import os
import pty
import select
import fcntl
import json
import sys

# Your recv_message and send_message helpers remain the same...
def recv_message(sock):
    raw_msglen = sock.recv(4)
    if not raw_msglen: return None
    msglen = struct.unpack('>I', raw_msglen)[0]
    return sock.recv(msglen).decode('utf-8')

def send_message(sock, msg):
    msg = msg.encode('utf-8')
    msg = struct.pack('>I', len(msg)) + msg
    sock.sendall(msg)

# We'll keep the simple execute_command for non-interactive stuff
def execute_simple_command(command, timeout_seconds=10):
    # This is the timeout-based function from Solution 1
    # ... (code from Solution 1) ...
    if not command: return {"status": "error", "result": "Received an empty command."}
    try:
        result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout_seconds)
        output_str = result.stdout.decode('utf-8') if result.stdout else "[command executed successfully with no output]"
        return {"status": "success", "result": output_str}
    except subprocess.TimeoutExpired:
        return {"status": "error", "result": "Command timed out after {} seconds.".format(timeout_seconds)}
    except subprocess.CalledProcessError as e:
        error_output_str = e.stderr.decode('utf-8') if e.stderr else e.stdout.decode('utf-8')
        return {"status": "error", "result": "Command failed with exit code {}:\n{}".format(e.returncode, error_output_str)}
    except Exception as e: return {"status": "error", "result": "An unexpected error occurred: {}".format(str(e))}


# This dictionary will hold the master file descriptor and PID of our interactive shells
interactive_sessions = {}

def start_interactive_session():
    """Starts a new interactive shell in a pseudo-terminal."""
    session_id = str(len(interactive_sessions))
    
    pid, master_fd = pty.fork()
    if pid == 0: # Child process
        # Start a new bash shell
        os.execvp('bash', ['bash'])
    else: # Parent process
        # Make the master file descriptor non-blocking
        fl = fcntl.fcntl(master_fd, fcntl.F_GETFL)
        fcntl.fcntl(master_fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
        
        interactive_sessions[session_id] = {'pid': pid, 'fd': master_fd}
        # Read the initial prompt
        initial_output = read_from_session(session_id)
        return {"status": "success", "session_id": session_id, "result": initial_output}

def read_from_session(session_id):
    """Reads all available output from a session without blocking."""
    if session_id not in interactive_sessions:
        return ""
    
    master_fd = interactive_sessions[session_id]['fd']
    output = ""
    while True:
        # select() waits until the fd is ready to be read, with a short timeout
        ready, _, _ = select.select([master_fd], [], [], 0.1)
        if not ready:
            break
        try:
            data = os.read(master_fd, 1024).decode('utf-8', errors='ignore')
            if not data: # EOF, shell has likely exited
                stop_interactive_session(session_id)
                break
            output += data
        except OSError:
            break
    return output

def write_to_session(session_id, command):
    """Writes a command to an interactive session."""
    if session_id not in interactive_sessions:
        return {"status": "error", "result": "Session not found."}
    
    master_fd = interactive_sessions[session_id]['fd']
    # Add a newline to execute the command
    full_command = command + '\n'
    os.write(master_fd, full_command.encode('utf-8'))
    # Give the command a moment to process and then read the output
    import time
    time.sleep(0.2)
    output = read_from_session(session_id)
    return {"status": "success", "result": output}

def stop_interactive_session(session_id):
    """Stops an interactive session."""
    if session_id in interactive_sessions:
        session = interactive_sessions.pop(session_id)
        os.close(session['fd'])
        try:
            # Terminate the process group to clean up any children
            os.killpg(os.getpgid(session['pid']), 9)
        except ProcessLookupError:
            pass # Process already gone
        return {"status": "success", "result": "Session {} closed.".format(session_id)}
    return {"status": "error", "result": "Session not found."}

# Main client loop needs to be updated to handle JSON commands
def start_client(host="127.0.0.1", port=65432):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((host, port))
        print("Connected to server.")
        while True:
            raw_data = recv_message(client_socket)
            if not raw_data: break
            
            response = {}
            try:
                # We'll assume the server sends JSON to control actions
                data = json.loads(raw_data)
                action = data.get("action")
                
                if action == "start_interactive":
                    response = start_interactive_session()
                elif action == "run_interactive":
                    session_id = data.get("session_id")
                    command = data.get("command")
                    response = write_to_session(session_id, command)
                elif action == "stop_interactive":
                    session_id = data.get("session_id")
                    response = stop_interactive_session(session_id)
                else: # Default to simple execution if action is unknown
                    response = execute_simple_command(data.get("command"))

            except json.JSONDecodeError:
                # Fallback for non-JSON commands
                response = execute_simple_command(raw_data)
            except Exception as e:
                response = {"status": "error", "result": "Client-side error: {}".format(str(e))}

            send_message(client_socket, json.dumps(response))
    print("Connection closed.")

if __name__ == "__main__":
    # Set default connection details.
    host = "127.0.0.1"
    port = 65432

    # sys.argv is a list: [script_name, argument1, argument2, ...]
    # We check if the user provided exactly two arguments (host and port).
    if len(sys.argv) == 3:
        host = sys.argv[1]  # The first argument is the host IP.
        try:
            # The second argument is the port, which we convert to an integer.
            port = int(sys.argv[2])
        except ValueError:
            # If the port argument isn't a valid number, print an error and exit.
            print("Error: Invalid port '{}'. Port must be an integer.".format(sys.argv[2]))
            sys.exit(1) # Exit the script with a status code indicating an error.
    elif len(sys.argv) > 1:
        # If the user provided some arguments, but not the correct number, show usage instructions.
        print("Usage: python your_client_script.py <host_ip> <port>")
        print("Example: python your_client_script.py 192.168.1.100 12345")
        sys.exit(1)

    # Call the start_client function with the specified host and port.
    start_client(host=host, port=port)
