# src/vault.py
import threading

class Vault:
    """Thread-safe shared vault for scrubber and descrubber."""
    def __init__(self):
        self.mapping = {}
        self._keys = []  # track insertion order
        self._lock = threading.Lock()

    def store(self, key, record):
        with self._lock:
            if key not in self.mapping:
                self._keys.append(key)
            self.mapping[key] = record

    def get(self, key):
        with self._lock:
            return self.mapping.get(key)

    def load_from_mapping(self, mapping: dict):
        """Merge an existing mapping (e.g., from scrubber)."""
        with self._lock:
            self.mapping.update(mapping)

    def all_keys(self):
        with self._lock:
            return list(self._keys)

# ✅ Create a global shared vault
global_vault = Vault()

