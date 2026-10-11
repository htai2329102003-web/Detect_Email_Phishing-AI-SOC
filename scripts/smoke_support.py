"""Lifecycle helpers for owned smoke processes and temporary test directories."""

import os
import subprocess
import tempfile
import time


class SmokeDirectory(tempfile.TemporaryDirectory):
    def cleanup(self):
        # Windows can briefly retain a SQLite handle after a worker exits.
        for _ in range(30):
            try:
                super().cleanup()
                return
            except PermissionError:
                time.sleep(0.1)
        super().cleanup()  # A persistent lock must still fail the smoke.


def stop_server(server):
    if server.poll() is None:
        if os.name == "nt":
            # The Windows venv launcher can have a Python child; stop our owned tree.
            subprocess.run(
                ["taskkill", "/PID", str(server.pid), "/T", "/F"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
        else:
            server.terminate()
    server.wait(timeout=10)
