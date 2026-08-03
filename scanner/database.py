import sqlite3

DATABASE = "cybershield.db"


def get_connection():
    conn = sqlite3.connect(DATABASE)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def initialize_database():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            target_type TEXT,
            scan_type TEXT,
            open_ports TEXT,
            total_files INTEGER,
            threats_found INTEGER,
            scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_scan_date ON scan_history(scan_date)"
    )

    conn.commit()
    conn.close()


def save_network_scan(target, target_type, ports):

    conn = get_connection()
    cursor = conn.cursor()

    open_ports = ", ".join(
        str(port["port"])
        for port in ports
    )

    cursor.execute("""
        SELECT id FROM scan_history
        WHERE target=?
        ORDER BY scan_date DESC, id DESC
        LIMIT 1
    """,(target,))

    if cursor.fetchone():
        pass

    cursor.execute("""
        INSERT INTO scan_history(
            target,
            target_type,
            scan_type,
            open_ports,
            total_files,
            threats_found
        )
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        target,
        target_type,
        "Network",
        open_ports,
        0,
        0
    ))

    conn.commit()
    conn.close()


def save_usb_scan(device_name, results):

    conn = get_connection()
    cursor = conn.cursor()

    threats = sum(
        1
        for file in results
        if file.get("status") != "CLEAN"
    )

    cursor.execute("""
        INSERT INTO scan_history(
            target,
            target_type,
            scan_type,
            open_ports,
            total_files,
            threats_found
        )
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        device_name,
        "USB",
        "USB Scan",
        "-",
        len(results),
        threats
    ))

    conn.commit()
    conn.close()


def save_scan(target, target_type, ports):
    """
    Compatibility wrapper for app.py
    """
    save_network_scan(target, target_type, ports)


def get_history():

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            target,
            target_type,
            scan_type,
            open_ports,
            total_files,
            threats_found,
            scan_date
        FROM scan_history
        ORDER BY scan_date DESC, id DESC
    """)

    rows = cursor.fetchall()

    conn.close()

    return rows
