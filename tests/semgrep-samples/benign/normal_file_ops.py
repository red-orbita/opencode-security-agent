# Benign sample: normal file operations
# This should NOT trigger any rules

import json
import os
from pathlib import Path

def read_config():
    """Read project configuration file."""
    config_path = Path("config.json")
    if config_path.exists():
        return json.loads(config_path.read_text())
    return {}

def save_results(data, output_path):
    """Save analysis results to file."""
    with open(output_path, "w") as f:
        json.dump(data, f, indent=2)

def get_project_name():
    """Get project name from environment or default."""
    return os.environ.get("PROJECT_NAME", "my-project")

def list_files(directory):
    """List files in a directory."""
    return [f.name for f in Path(directory).iterdir() if f.is_file()]
