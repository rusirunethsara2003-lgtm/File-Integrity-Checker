
import hashlib
import json
from pathlib import Path
from datetime import datetime

# Project folder
BASE_DIR = Path(__file__).resolve().parent

# Baseline and log files
BASELINE = BASE_DIR / "baseline.json"
LOG_FILE = BASE_DIR / "security_log.txt"

# Files to monitor
FILES = [
    "test.txt",
    "config.txt",
    "notes.txt",
    "security.txt"
]


# Calculate SHA-256 hash
def calculate_hash(path):
    sha256 = hashlib.sha256()

    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(65536), b""):
            sha256.update(chunk)

    return sha256.hexdigest()


# Save security alerts
def log_alert(status, filename):
    time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with LOG_FILE.open("a", encoding="utf-8") as log:
        log.write(f"{time} [{status}] {filename}\n")


# Main program
def main():
    current_hashes = {}

    # Calculate current file hashes
    for filename in FILES:
        path = BASE_DIR / filename

        if path.is_file():
            current_hashes[filename] = calculate_hash(path)

    # Create baseline if it does not exist
    if not BASELINE.exists():
        BASELINE.write_text(
            json.dumps(current_hashes, indent=2),
            encoding="utf-8"
        )

        print("Baseline created successfully!")
        print("Run the program again to check files.")
        return

    # Load saved baseline
    try:
        saved_hashes = json.loads(
            BASELINE.read_text(encoding="utf-8")
        )

        if not isinstance(saved_hashes, dict):
            raise ValueError("Invalid baseline format")

    except (ValueError, OSError):
        print("ERROR: Invalid baseline.json")
        return

    print("\nFILE INTEGRITY REPORT")
    print("---------------------")

    # Compare saved and current hashes
    for filename in FILES:
        old_hash = saved_hashes.get(filename)
        new_hash = current_hashes.get(filename)

        if old_hash is None and new_hash is not None:
            print(f"[NEW] {filename}")
            log_alert("NEW", filename)

        elif old_hash is not None and new_hash is None:
            print(f"[DELETED] {filename}")
            log_alert("DELETED", filename)

        elif old_hash != new_hash:
            print(f"[MODIFIED] {filename}")
            log_alert("MODIFIED", filename)

        else:
            print(f"[UNCHANGED] {filename}")

    print("\nSecurity scan completed!")


if __name__ == "__main__":
    main()
