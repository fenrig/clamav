#!/usr/bin/env python3
"""Native messaging bridge for the ClamAV Thunderbird extension."""

import json
import hashlib
import os
import struct
import subprocess
import sys


def failure(message, sha256=None):
    result = {"success": False, "infected": False, "message": message}
    if sha256 is not None:
        result["sha256"] = sha256
    return result


def read_message():
    size_data = sys.stdin.buffer.read(4)
    if len(size_data) != 4:
        return None
    size = struct.unpack("<I", size_data)[0]
    return json.loads(sys.stdin.buffer.read(size))


def write_message(message):
    data = json.dumps(message).encode("utf-8")
    sys.stdout.buffer.write(struct.pack("<I", len(data)))
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()


def scan(path):
    display_name = os.path.basename(path)
    try:
        with open(path, "rb") as sample:
            sha256 = hashlib.sha256(sample.read()).hexdigest()
    except OSError as error:
        return failure(f"Unable to read attachment: {error}")

    # Embedded images in otherwise valid office documents can trip ClamAV's
    # broken-media heuristic. Keep that heuristic disabled for this helper;
    # it is not a malware signature and otherwise makes ordinary documents
    # appear infected to the add-on.
    scanner = ["clamscan", "--infected", "--alert-broken-media=no", path]
    scanner_name = "clamscan"
    try:
        try:
            daemon_available = subprocess.run(
                ["clamdscan", "--ping", "1"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False).returncode == 0
        except OSError:
            daemon_available = False
        if daemon_available:
            scanner = ["clamdscan", "--infected", path]
            scanner_name = "clamdscan"
        completed = subprocess.run(scanner, text=True, capture_output=True,
                                   check=False)
        # clamd takes AlertBrokenMedia from its daemon configuration, so the
        # per-scan clamscan option cannot be passed through clamdscan. Retry a
        # daemon heuristic result locally with that alert disabled so the
        # Thunderbird integration behaves consistently in both modes.
        output = completed.stdout + completed.stderr
        if (scanner_name == "clamdscan" and completed.returncode == 1
                and "Broken.Media" in output):
            fallback = subprocess.run(
                ["clamscan", "--infected", "--alert-broken-media=no", path],
                text=True, capture_output=True, check=False)
            if fallback.returncode in (0, 1):
                completed = fallback
                scanner_name = "clamscan"
    except OSError as error:
        return failure(f"Unable to start ClamAV: {error}", sha256)

    output = (completed.stdout + completed.stderr).strip()
    # ClamAV includes the input path in its output. The path points to the
    # temporary Thunderbird download and should not be shown to the user.
    output = output.replace(path, display_name)
    output = output.replace(os.path.abspath(path), display_name)
    try:
        version = subprocess.run([scanner_name, "--version"], text=True,
                                 capture_output=True, check=False)
        version_lines = (version.stdout + version.stderr).strip().splitlines()
        version_text = version_lines[0] if version_lines else "unknown"
    except OSError:
        version_text = "unknown"
    details = "Detection: " + (output or "none")
    details += "\nSHA-256: " + sha256
    details += "\nScanner: " + version_text
    if completed.returncode == 0:
        message = "No viruses found.\n\n" + details
    elif completed.returncode == 1:
        message = "A virus was identified.\n\n" + details
    else:
        return failure("The scan could not be completed.\n\n" + details, sha256)
    return {"success": True, "infected": completed.returncode == 1,
            "message": message, "sha256": sha256}


while True:
    request = read_message()
    if request is None:
        break
    write_message(scan(request["path"]))
