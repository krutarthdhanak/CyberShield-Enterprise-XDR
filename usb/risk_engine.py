def calculate_risk(results):
    """
    Calculate the overall USB scan risk.

    Priority:
    INFECTED  -> CRITICAL
    SUSPICIOUS -> HIGH
    CLEAN      -> LOW
    """

    has_suspicious = False

    for item in results:
        status = str(item.get("status", "")).upper()
        reason = str(item.get("reason", "")).upper()

        if status == "INFECTED":
            return "CRITICAL"

        if status == "SUSPICIOUS" or "SUSPICIOUS" in reason:
            has_suspicious = True

    if has_suspicious:
        return "HIGH"

    return "LOW"
