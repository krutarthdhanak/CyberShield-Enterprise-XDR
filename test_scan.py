from usb.file_scanner import scan_folder
from usb.hashing import sha256_hash
from usb.malware import malware_check

print("\n===================================")
print(" CyberShield USB Security Scanner ")
print("===================================\n")

files = scan_folder("test_usb")

if not files:
    print("No files found.")
    exit()

high_count = 0

for file in files:

    file_hash = sha256_hash(file["path"])

    status, reason = malware_check(file["path"])

    if status == "SUSPICIOUS":
        high_count += 1

    print("=" * 70)
    print(f"Name       : {file['name']}")
    print(f"Extension  : {file['extension']}")
    print(f"Size       : {file['size']} bytes")
    print(f"Risk       : {file['risk']}")
    print(f"SHA256     : {file_hash}")
    print(f"Malware    : {status}")
    print(f"Reason     : {reason}")
    print(f"Path       : {file['path']}")

print("\n===================================")
print("Scan Summary")
print("===================================")
print(f"Files Scanned      : {len(files)}")
print(f"Suspicious Files   : {high_count}")
print(f"Safe Files         : {len(files)-high_count}")
print("===================================\n")
