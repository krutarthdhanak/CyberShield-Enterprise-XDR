"""
CyberShield Enterprise XDR
USB Risk Assessment Engine
"""

DANGEROUS_EXTENSIONS = {
    ".exe",
    ".dll",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".js",
    ".scr",
    ".com",
    ".jar",
    ".msi"
}


def calculate_risk(scan_results):
    """
    Calculate overall USB risk.
    Returns a dictionary with score, level and recommendations.
    """

    total_files = len(scan_results)
    suspicious = 0
    dangerous = 0
    malware = 0

    for file in scan_results:

        status = file.get("status", "CLEAN").upper()
        ext = file.get("extension", "").lower()

        if status != "CLEAN":
            suspicious += 1

        if ext in DANGEROUS_EXTENSIONS:
            dangerous += 1

        if status in ("MALWARE", "INFECTED", "DANGEROUS"):
            malware += 1

    score = (
        suspicious * 15 +
        dangerous * 10 +
        malware * 30
    )

    score = min(score, 100)

    if score >= 80:
        level = "CRITICAL"
    elif score >= 60:
        level = "HIGH"
    elif score >= 30:
        level = "MEDIUM"
    else:
        level = "LOW"

    recommendations = []

    if malware:
        recommendations.append(
            "Immediately isolate the USB device."
        )

    if dangerous:
        recommendations.append(
            "Review executable files before opening."
        )

    if suspicious:
        recommendations.append(
            "Run a full malware scan."
        )

    if not recommendations:
        recommendations.append(
            "No immediate action required."
        )

    return {
        "risk_score": score,
        "risk_level": level,
        "total_files": total_files,
        "suspicious_files": suspicious,
        "dangerous_files": dangerous,
        "malware_detected": malware,
        "recommendations": recommendations
    }
