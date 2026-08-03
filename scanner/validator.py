import ipaddress
import re

def validate_target(target):
    target = target.strip()

    try:
        ipaddress.ip_address(target)
        return True, "IP Address"
    except ValueError:
        pass

    domain_pattern = r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"

    if re.match(domain_pattern, target):
        return True, "Domain"

    return False, "Invalid"
