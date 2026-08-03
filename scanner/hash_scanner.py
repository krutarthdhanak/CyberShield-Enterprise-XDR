"""
CyberShield Enterprise XDR
Hash Scanner
"""

import hashlib
import json
import os

SIGNATURE_DB = "signatures/malware_hashes.json"


def sha256(file_path):
    """
    Calculate SHA-256 hash of a file.
    """
    hasher = hashlib.sha256()

    with open(file_path, "rb") as f:
        while True:
            data = f.read(8192)
            if not data:
                break
            hasher.update(data)

    return hasher.hexdigest()


def load_signatures():
    """
    Load malware hash database.
    """
    if not os.path.exists(SIGNATURE_DB):
        return {}

    try:
        with open(SIGNATURE_DB, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def check_hash(file_path):
    """
    Compare a file hash against known malware hashes.
    """
    signatures = load_signatures()

    file_hash = sha256(file_path)

    if file_hash in signatures:
        return {
            "status": "MALWARE",
            "hash": file_hash,
            "reason": signatures[file_hash]
        }

    return {
        "status": "CLEAN",
        "hash": file_hash,
        "reason": "Hash not found in signature database"
    }
