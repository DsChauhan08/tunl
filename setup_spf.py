import socket
import time

def read_until_prompt(s):
    data = b""
    while not data.endswith(b"> "):
        chunk = s.recv(1024)
        if not chunk: break
        data += chunk
    return data.decode()

def send_cmd(cmd, port=8081, token="secret"):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
            read_until_prompt(s) # Skip banner
            s.sendall(f"AUTH {token}\n".encode())
            auth_res = read_until_prompt(s)
            print(f"Auth result: {auth_res.strip()}")
            
            s.sendall(f"{cmd}\n".encode())
            cmd_res = read_until_prompt(s)
            print(f"Sent: {cmd}")
            print(f"Received: {cmd_res.strip()}")
            
            s.sendall(b"QUIT\n")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    send_cmd("ADD 8080 127.0.0.1:9000 rr")
    time.sleep(1)
    send_cmd("RULES")
