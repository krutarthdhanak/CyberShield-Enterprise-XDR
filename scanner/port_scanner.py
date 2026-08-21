import socket
from concurrent.futures import ThreadPoolExecutor


def grab_banner(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((ip, port))

        if port in [80, 8080]:
            s.send(b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n")

        banner = s.recv(1024).decode(errors="ignore").strip()

        s.close()

        if banner == "":
            banner = "Banner Not Available"

        return banner

    except Exception:
        return "Banner Not Available"


def scan_single_port(target_ip, port):

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.25)

    result = s.connect_ex((target_ip, port))

    if result != 0:
        s.close()
        return None

    try:
        service = socket.getservbyport(port)
    except Exception:
        service = "Unknown"

    banner = grab_banner(target_ip, port)

    risk = "Low"
    recommendation = "No immediate concern."

    if port == 21:
        risk = "Medium"
        recommendation = "FTP detected. Use SFTP instead."

    elif port == 23:
        risk = "High"
        recommendation = "Telnet is insecure. Use SSH instead."

    elif port == 80:
        risk = "Medium"
        recommendation = "HTTP detected. Consider enabling HTTPS."

    elif port == 445:
        risk = "High"
        recommendation = "SMB exposed. Restrict access if not required."

    elif port == 3389:
        risk = "High"
        recommendation = "Remote Desktop exposed. Protect it with a VPN."

    s.close()

    return {
        "port": port,
        "service": service,
        "banner": banner,
        "risk": risk,
        "recommendation": recommendation
    }


def scan_ports(target, start_port, end_port):

    open_ports = []

    # Resolve hostname once
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        raise Exception(f"Unable to resolve hostname: {target}")

    port_range = range(start_port, end_port + 1)

    with ThreadPoolExecutor(max_workers=50) as executor:

        results = executor.map(
            lambda port: scan_single_port(target_ip, port),
            port_range
        )

    for result in results:
        if result is not None:
            open_ports.append(result)

    return sorted(open_ports, key=lambda x: x["port"])
