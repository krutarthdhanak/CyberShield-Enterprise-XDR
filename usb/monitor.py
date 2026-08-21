from scanner.report import generate_usb_report
import os
import time
import threading
import subprocess
import glob

from usb.usb_scanner import scan_usb
from scanner.database import save_usb_scan, log_xdr_event

usb_connected = False
last_results = []
last_scan_time = ""
last_usb = None
last_risk = None

# Latest automatic scan (used by app.py)
latest_scan = None

MOUNT_DIR = "/media/root/USB"
CHECK_INTERVAL = 2

current_device = None
last_logged_device = None
last_logged_scan_time = 0



def get_usb_device():
    try:
        devices = sorted(glob.glob("/dev/sd*"))

        # Ignore Kali system disk
        devices = [
            d for d in devices
            if not d.startswith("/dev/sda")
        ]

        # Prefer partitions
        for d in devices:
            if d[-1].isdigit():
                return d

        if devices:
            return devices[0]

    except Exception as e:
        print("[XDR] Detection Error:", e)

    return None


def mount_usb(device):

    os.makedirs(MOUNT_DIR, exist_ok=True)

    try:
        mounts = subprocess.check_output(
            ["mount"],
            text=True
        )

        # Already mounted
        for line in mounts.splitlines():
            if line.startswith(device + " "):
                return True

        subprocess.run(
            ["mount", device, MOUNT_DIR],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        return True

    except Exception as e:
        print("[XDR] Mount Error:", e)
        return False


def unmount_usb():

    try:
        subprocess.run(
            ["umount", MOUNT_DIR],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
    except Exception:
        pass


def monitor_usb():

    global usb_connected
    global last_results
    global last_scan_time
    global last_usb
    global last_risk
    global latest_scan
    global current_device
    global last_logged_device
    global last_logged_scan_time

    print("=" * 60)
    print("CyberShield Enterprise XDR USB Monitor Started")
    print("=" * 60)

    while True:

        device = get_usb_device()


        # USB Inserted
        if device and current_device is None:

            print(f"[XDR] USB Detected : {device}")

            if mount_usb(device):

                print("[XDR] USB Mounted")

                current_device = device
                usb_connected = True
                last_usb = MOUNT_DIR                # Automatically scan USB
                report = scan_usb(MOUNT_DIR)

                latest_scan = report

                last_results = report["results"]
                last_risk = report["risk"]
                last_scan_time = time.strftime("%Y-%m-%d %H:%M:%S")

                # Save scan to database
                save_usb_scan(
                    os.path.basename(device),
                    last_results
                )

                # Log USB activity into the XDR event system
                infected_count = sum(
                    1
                    for item in last_results
                    if str(item.get("status", "")).upper() == "INFECTED"
                )

                suspicious_count = sum(
                    1
                    for item in last_results
                    if str(item.get("status", "")).upper() == "SUSPICIOUS"
                )

                device_name = os.path.basename(device)
                now = time.time()

                # Prevent duplicate XDR events
                duplicate_event = (
                    device_name == last_logged_device
                    and (now - last_logged_scan_time) < 60
                )

                if not duplicate_event:

                    if infected_count > 0:
                        log_xdr_event(
                            "USB_THREAT_DETECTED",
                            "CRITICAL",
                            "USB Scanner",
                            f"USB {device_name}: "
                            f"{infected_count} infected files detected"
                        )

                    elif suspicious_count > 0:
                        log_xdr_event(
                            "USB_SUSPICIOUS_ACTIVITY",
                            "HIGH",
                            "USB Scanner",
                            f"USB {device_name}: "
                            f"{suspicious_count} suspicious files detected"
                        )

                    else:
                        log_xdr_event(
                            "USB_SCAN_COMPLETED",
                            "INFO",
                            "USB Scanner",
                            f"USB {device_name}: "
                            f"{len(last_results)} files scanned, no threats detected"
                        )

                    last_logged_device = device_name
                    last_logged_scan_time = now

                # Automatically generate PDF report
                pdf_file = generate_usb_report(
                    os.path.basename(device),
                    last_results
                )

                print(f"[XDR] PDF Generated: {pdf_file}")
                print("[XDR] Automatic Scan Completed")

            else:
                print("[XDR] USB Mount Failed")        # USB Removed
        elif device is None and current_device is not None:

            print("[XDR] USB Removed")

            unmount_usb()

            current_device = None
            usb_connected = False
            last_results = []
            last_risk = None
            last_usb = None
            latest_scan = None

        time.sleep(CHECK_INTERVAL)


def start_monitor():

    thread = threading.Thread(
        target=monitor_usb,
        daemon=True
    )

    thread.start()

if __name__ == "__main__":
    monitor_usb()
