from pathlib import Path
import json

LEVELS = ("INFO", "WARN", "ERROR")

def read_log_file(path):
    return Path(path).read_text(encoding="utf-8")

def count_log_levels(text):
    counter = {level: 0 for level in LEVELS}

    for line in text.splitlines():
        if not line.strip():
            continue

        try:
            log = json.loads(line)
            level = log.get("level")

            if level in counter:
                counter[level] += 1

        except json.JSONDecodeError:
            continue

    return counter