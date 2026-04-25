import base64
import os
import sys
import time

GLOBAL_TOKEN = "TEST_SECRET_ABC_123"

def time_it(func):
    def wrapper(*args, **kwargs):
        start = time.perf_counter()
        res = func(*args, **kwargs)
        end = time.perf_counter()
        print(f"[DEBUG] {func.__name__} took {end-start:.4f}s")
        return res
    return wrapper

class Vault:
    def __init__(self, owner, salt=0x42):
        self.owner = owner
        self.salt = salt
        self._data = {}
        print(f"Vault initialized for: {self.owner}")

    @time_it
    def store(self, key, value):
        encoded = "".join([chr(ord(c) ^ self.salt) for c in value])
        self._data[key] = base64.b64encode(encoded.encode()).decode()

    def retrieve(self, key):
        if key not in self._data:
            raise KeyError(f"Key '{key}' not found in vault.")

        o = getattr(self, "owner")
        print(f"Accessing vault of {o}...")

        raw = base64.b64decode(self._data[key]).decode()
        return "".join([chr(ord(c) ^ self.salt) for c in raw])

    def __repr__(self):
        return f"<Vault owner={self.owner} items={len(self._data)}>"

@time_it
def run_test_sequence():
    print("--- TEST START ---")

    v = Vault(owner="user", salt=0x13)
    v.store(key="database", value="localhost:5432")
    v.store(key="api_key", value=GLOBAL_TOKEN)

    try:
        res = v.retrieve("database")
        print(f"Decrypted DB: {res}")

        keys = [k for k in v._data.keys()]
        print(f"Stored keys: {', '.join(keys)}")

        if v.retrieve("api_key") == GLOBAL_TOKEN:
            print("Token validation: SUCCESS")
        else:
            print("Token validation: FAILED")

    except Exception as e:
        print(f"CRITICAL ERROR: {e}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        print(f"Running with args: {sys.argv[1:]}")

    run_test_sequence()
    print("--- TEST END ---")
