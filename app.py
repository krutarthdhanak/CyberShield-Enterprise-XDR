from flask import jsonify, Flask, render_template, request, send_file, flash, redirect
import os
import glob
import subprocess
import time

from scanner.validator import validate_target
from scanner.port_scanner import scan_ports
from scanner.report import generate_report
from scanner.database import initialize_database, save_scan, get_history
import usb.monitor as monitor
from usb.monitor import start_monitor

app = Flask(__name__)
app.secret_key = os.urandom(24)

initialize_database()


def get_usb_path():
    start_time = time.time()

    try:
        output = subprocess.check_output(
            ["lsblk", "-o", "NAME,RM,TYPE,MOUNTPOINT", "-nr"],
            text=True
        )

        for line in output.splitlines():
            parts = line.split(None, 3)

            if len(parts) < 4:
                continue

            name, rm, dev_type, mountpoint = parts

            if rm == "1" and dev_type == "part" and mountpoint:
                return mountpoint

    except Exception as e:
        print("USB Detection Error:", e)

    return None


last_target = None
last_target_type = None
last_ports = []
last_start_port = None
last_end_port = None
last_scan_time = "Never"



@app.route("/")
def home(error=None):

    usb_path = monitor.last_usb if monitor.usb_connected else None

    scans = get_history()

    total_scans = len(scans)

    # Dashboard statistics based on latest network scan
    total_open_ports = len(last_ports)

    high_risk = sum(1 for p in last_ports if p["risk"] == "High")
    medium_risk = sum(1 for p in last_ports if p["risk"] == "Medium")
    low_risk = sum(1 for p in last_ports if p["risk"] == "Low")

    security_score = max(
        0,
        100 - (high_risk * 15 + medium_risk * 7 + low_risk * 2)
    )

    return render_template(
        "index.html",
        usb_connected=monitor.usb_connected,
        usb_mount=usb_path,
        total_scans=total_scans,
        total_open_ports=total_open_ports,
        high_risk=high_risk,
        medium_risk=medium_risk,
        low_risk=low_risk,
        security_score=security_score,
        usb_results=monitor.latest_scan,
        usb_risk=monitor.last_risk,
        ports=last_ports,
        target=last_target,
        target_type=last_target_type,
        start_port=last_start_port,
        end_port=last_end_port,
        last_scan_time=last_scan_time,
        error=error,
    )


@app.route("/scan", methods=["POST"])
def scan():
    global last_target, last_target_type
    global last_ports, last_start_port, last_end_port
    global last_scan_time

    target = request.form.get("target", "").strip()

    try:
        start_port = int(request.form.get("start_port", ""))
        end_port = int(request.form.get("end_port", ""))
    except (ValueError, TypeError):
        return home("Port numbers must be valid numeric values.")

    valid, target_type = validate_target(target)

    if not valid:
        return home("Invalid IP Address or Domain")

    if start_port < 1 or end_port > 65535:
        return home("Port numbers must be between 1 and 65535.")

    if start_port > end_port:
        return home("Start Port must be less than End Port.")

    start_time = time.time()

    try:
        ports = scan_ports(target, start_port, end_port)
    except Exception as e:
        print("Scan Error:", e)
        return home("Please check your target and try again.") 

    last_target = target
    last_target_type = target_type
    last_ports = ports
    last_start_port = start_port
    last_end_port = end_port

    from datetime import datetime
    last_scan_time = datetime.now().strftime("%d-%m-%Y %H:%M:%S")


    scan_duration = round(time.time()-start_time,2)

    print(f"Scan completed in {scan_duration} seconds")

    save_scan(target, target_type, ports)

    return home()




@app.route("/status")
def status():
    return jsonify({
        "usb_connected": monitor.usb_connected,
        "usb_mount": monitor.last_usb,
        "usb_risk": monitor.last_risk,
        "usb_results": monitor.latest_scan,
        "last_scan_time": monitor.last_scan_time
    })

@app.route("/download_report")
def download_report():

    if last_target is None or not last_ports:
        return "<h2>No completed scan available.</h2>"

    pdf = generate_report(
        last_target,
        last_target_type,
        last_ports
    )

    return send_file(pdf, as_attachment=True)




@app.route("/download_usb_report")
def download_usb_report():
    reports = sorted(
        glob.glob("reports/usb_scan_*.pdf"),
        key=os.path.getmtime,
        reverse=True
    )

    if not reports:
        return "No USB reports found.", 404

    return send_file(
        reports[0],
        as_attachment=True
    )

@app.route("/history")
def history():
    return render_template(
        "history.html",
        scans=get_history()
    )


if __name__ == "__main__":
    start_monitor()
    app.run(debug=False, threaded=True, use_reloader=False)
