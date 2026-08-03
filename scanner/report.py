from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.colors import HexColor
import os
import time
from datetime import datetime

REPORT_DIR = "reports"


def ensure_folder():
    if not os.path.exists(REPORT_DIR):
        os.makedirs(REPORT_DIR)


def draw_header(c, title):
    width, height = letter

    c.setFillColor(HexColor("#0F172A"))
    c.rect(0, height - 70, width, 70, fill=1, stroke=0)

    c.setFillColor(HexColor("#38BDF8"))
    c.setFont("Helvetica-Bold", 22)
    c.drawString(40, height - 42, "CyberShield Enterprise XDR")

    c.setFillColor(HexColor("#FFFFFF"))
    c.setFont("Helvetica", 10)
    c.drawString(
        40,
        height - 58,
        "Enterprise Vulnerability Assessment & USB Threat Detection Platform"
    )

    c.setFillColor(HexColor("#111827"))
    c.setFont("Helvetica-Bold", 17)
    c.drawString(40, height - 95, title)

    return height - 125


def draw_footer(c):
    width, _ = letter

    c.setStrokeColor(HexColor("#CBD5E1"))
    c.line(40, 35, width - 40, 35)

    c.setFont("Helvetica", 9)
    c.setFillColor(HexColor("#475569"))

    c.drawString(
        40,
        20,
        "CyberShield Enterprise XDR v2.0 | Developed by Krutarth Dhanak"
    )

    c.drawRightString(
        width - 40,
        20,
        datetime.now().strftime("%d-%m-%Y %H:%M:%S")
    )


def generate_report(target, target_type, ports):

    ensure_folder()

    filename = os.path.join(
        REPORT_DIR,
        f"network_scan_{int(time.time())}.pdf"
    )

    c = canvas.Canvas(filename, pagesize=letter)

    y = draw_header(c, "Network Security Assessment Report")

    high = sum(1 for p in ports if p["risk"] == "High")
    medium = sum(1 for p in ports if p["risk"] == "Medium")
    low = sum(1 for p in ports if p["risk"] == "Low")

    score = max(0, 100 - (high * 15 + medium * 7 + low * 2))

    # Executive Summary
    c.setFillColor(HexColor("#111827"))
    c.setFont("Helvetica-Bold", 15)
    c.drawString(40, y, "Executive Summary")

    y -= 25

    c.setFont("Helvetica", 11)

    c.drawString(45, y, f"Target : {target}")
    y -= 18

    c.drawString(45, y, f"Target Type : {target_type}")
    y -= 18

    c.drawString(45, y, f"Total Open Ports : {len(ports)}")
    y -= 18

    c.drawString(45, y, f"Security Score : {score}%")
    y -= 18

    c.drawString(
        45,
        y,
        f"Generated : {datetime.now().strftime('%d-%m-%Y %H:%M:%S')}"
    )

    y -= 35

    c.setFont("Helvetica-Bold", 15)
    c.drawString(40, y, "Risk Summary")

    y -= 22

    c.setFont("Helvetica", 11)

    c.drawString(45, y, f"High Risk Findings : {high}")
    y -= 18

    c.drawString(45, y, f"Medium Risk Findings : {medium}")
    y -= 18

    c.drawString(45, y, f"Low Risk Findings : {low}")

    y -= 35

    c.setFont("Helvetica-Bold", 15)
    c.drawString(40, y, "Discovered Services")

    y -= 25

    c.setFillColor(HexColor("#E2E8F0"))
    c.rect(40, y - 5, 520, 20, fill=1)

    c.setFillColor(HexColor("#000000"))
    c.setFont("Helvetica-Bold", 10)

    c.drawString(45, y, "PORT")
    c.drawString(100, y, "SERVICE")
    c.drawString(190, y, "BANNER")
    c.drawString(330, y, "RISK")
    c.drawString(400, y, "RECOMMENDATION")

    y -= 22

    c.setFont("Helvetica", 9)

    for port in ports:

        if y < 80:

            draw_footer(c)
            c.showPage()

            y = draw_header(c, "Discovered Services")

            c.setFillColor(HexColor("#E2E8F0"))
            c.rect(40, y - 5, 520, 20, fill=1)

            c.setFillColor(HexColor("#000000"))
            c.setFont("Helvetica-Bold", 10)

            c.drawString(45, y, "PORT")
            c.drawString(100, y, "SERVICE")
            c.drawString(190, y, "BANNER")
            c.drawString(330, y, "RISK")
            c.drawString(400, y, "RECOMMENDATION")

            y -= 22
            c.setFont("Helvetica", 9)

        risk = port["risk"]

        if risk == "High":
            c.setFillColor(HexColor("#DC2626"))
        elif risk == "Medium":
            c.setFillColor(HexColor("#D97706"))
        else:
            c.setFillColor(HexColor("#15803D"))

        c.drawString(45, y, str(port["port"]))

        c.setFillColor(HexColor("#000000"))

        c.drawString(100, y, port["service"])

        banner = port.get("banner","N/A")
        c.drawString(190, y, banner[:18])
        c.drawString(330, y, risk)

        recommendation = port.get(
            "recommendation",
            "Review configuration"
        )

        c.drawString(
            400,
            y,
            recommendation[:22]
        )

        y -= 18
    # -------------------------------
    # Executive Recommendations
    # -------------------------------

    y -= 20

    if y < 170:
        draw_footer(c)
        c.showPage()
        y = draw_header(c, "Security Recommendations")

    c.setFillColor(HexColor("#111827"))
    c.setFont("Helvetica-Bold", 15)
    c.drawString(40, y, "Executive Recommendations")

    y -= 25

    c.setFont("Helvetica", 11)

    recommendations = []

    if high > 0:
        recommendations.append(
            "• Immediately investigate and secure HIGH risk services."
        )

    if medium > 0:
        recommendations.append(
            "• Restrict MEDIUM risk services using firewall rules."
        )

    if low > 0:
        recommendations.append(
            "• Continue monitoring LOW risk services."
        )

    recommendations.extend([
        "• Keep operating systems updated.",
        "• Disable unused network services.",
        "• Enable endpoint protection.",
        "• Review firewall configuration regularly.",
        "• Perform regular vulnerability assessments.",
        "• Enable centralized log monitoring."
    ])

    for rec in recommendations:

        if y < 70:
            draw_footer(c)
            c.showPage()
            y = draw_header(c, "Security Recommendations")
            c.setFont("Helvetica", 11)

        c.drawString(50, y, rec)
        y -= 18

    y -= 15

    if y < 120:
        draw_footer(c)
        c.showPage()
        y = draw_header(c, "Overall Assessment")

    c.setFont("Helvetica-Bold", 15)
    c.drawString(40, y, "Overall Assessment")

    y -= 25

    if high > 0:
        rating = "HIGH"
        color = HexColor("#DC2626")
    elif medium > 0:
        rating = "MEDIUM"
        color = HexColor("#D97706")
    else:
        rating = "LOW"
        color = HexColor("#15803D")

    c.setFillColor(color)
    c.setFont("Helvetica-Bold", 18)
    c.drawString(45, y, f"Overall Risk Rating : {rating}")

    y -= 30

    c.setFillColor(HexColor("#111827"))
    c.setFont("Helvetica", 11)

    c.drawString(
        45,
        y,
        "This report was automatically generated by CyberShield Enterprise XDR."
    )

    y -= 18

    c.drawString(
        45,
        y,
        "The assessment is based on the discovered open services during the scan."
    )

    y -= 30

    c.setFont("Helvetica-Bold",14)
    c.drawString(40,y,"Business Impact")

    y -= 20

    c.setFont("Helvetica",11)

    if rating=="HIGH":
        impact="Immediate remediation is recommended due to high-risk exposure."
    elif rating=="MEDIUM":
        impact="Security hardening is recommended to reduce attack surface."
    else:
        impact="Current exposure is low. Continue periodic monitoring."

    c.drawString(45,y,impact)

    draw_footer(c)

    c.save()

    return filename


def generate_usb_report(usb_name, results):
    ensure_folder()

    filename = os.path.join(
        REPORT_DIR,
        f"usb_scan_{int(time.time())}.pdf"
    )

    c = canvas.Canvas(filename, pagesize=letter)

    y = draw_header(c, "USB Malware Scan Report")

    total = len(results)
    suspicious = sum(
        1 for r in results
        if r.get("status", "").upper() != "CLEAN"
    )

    score = max(0, 100 - suspicious * 10)

    c.setFont("Helvetica-Bold", 15)
    c.drawString(40, y, "Executive Summary")

    y -= 25

    c.setFont("Helvetica", 11)

    c.drawString(45, y, f"USB Device : {usb_name}")
    y -= 18

    c.drawString(45, y, f"Files Scanned : {total}")
    y -= 18

    c.drawString(45, y, f"Suspicious Files : {suspicious}")
    y -= 18

    c.drawString(45, y, f"Security Score : {score}%")

    y -= 35

    c.setFont("Helvetica-Bold", 15)
    c.drawString(40, y, "Scan Results")

    y -= 22

    c.setFont("Helvetica-Bold", 10)

    c.drawString(45, y, "FILE")
    c.drawString(260, y, "STATUS")
    c.drawString(360, y, "RISK")

    y -= 18

    c.setFont("Helvetica", 9)

    for item in results:

        if y < 70:
            draw_footer(c)
            c.showPage()
            y = draw_header(c, "USB Scan Results")

        c.drawString(
            45,
            y,
            str(item.get("name", ""))[:35]
        )

        c.drawString(
            260,
            y,
            item.get("status", "")
        )

        c.drawString(
            360,
            y,
            item.get("risk", "")
        )

        y -= 16

    draw_footer(c)

    c.save()

    return filename
