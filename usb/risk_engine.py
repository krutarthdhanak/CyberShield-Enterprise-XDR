def calculate_risk(results):
    """
    Calculate USB scan risk based on scanned files.
    """

    risk = "LOW"

    for item in results:
        status = str(item.get("status", "")).upper()
        reason = str(item.get("reason", "")).upper()

        if status == "INFECTED":
            return "HIGH"

        if "SUSPICIOUS" in reason or status == "SUSPICIOUS":
            risk = "MEDIUM"

    return risk