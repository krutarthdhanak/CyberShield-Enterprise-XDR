from usb.file_scanner import scan_folder
from usb.hashing import sha256_hash
from usb.malware import malware_check
from usb.risk_engine import calculate_risk


def scan_usb(folder="test_usb"):
    """
    Complete USB scan.
    """

    files = scan_folder(folder)

    results = []

    for file in files:

        try:
            file_hash = sha256_hash(file["path"])

            status, reason = malware_check(
                file["path"],
                file_hash
            )

            results.append({
                "name": file["name"],
                "path": file["path"],
                "size": file["size"],
                "extension": file["extension"],
                "risk": file["risk"],
                "sha256": file_hash,
                "status": status,
                "reason": reason
            })

        except Exception as e:

            results.append({
                "name": file["name"],
                "path": file["path"],
                "size": file["size"],
                "extension": file["extension"],
                "risk": "UNKNOWN",
                "sha256": "",
                "status": "ERROR",
                "reason": str(e)
            })

    risk = calculate_risk(results)

    return {
        "results": results,
        "risk": risk
    }

