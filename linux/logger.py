# logger.py
"""
Simple synchronous logger for MP-Hardener.
Writes messages to a specified log file and optionally echoes to stdout.
"""

import datetime
from pathlib import Path


class SimpleLogger:
    def __init__(self, logfile: Path, verbose: bool = False):
        self.logfile = logfile
        self.verbose = verbose

        logfile.parent.mkdir(parents=True, exist_ok=True)
        if not logfile.exists():
            logfile.touch(mode=0o600)

    def log(self, level: str, message: str):
        timestamp = datetime.datetime.now().isoformat()
        line = f"[{timestamp}] {level.upper():<7} {message}\n"

        with open(self.logfile, "a", encoding="utf-8") as f:
            f.write(line)

