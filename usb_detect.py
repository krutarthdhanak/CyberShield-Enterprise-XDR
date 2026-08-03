import psutil

usb_found = False

print("Searching for USB devices...\n")

for partition in psutil.disk_partitions():
    if partition.mountpoint == "/mnt/usb":
        usb_found = True
        print("✅ USB Detected")
        print(f"Device      : {partition.device}")
        print(f"Mount Point : {partition.mountpoint}")
        print(f"File System : {partition.fstype}")

if not usb_found:
    print("❌ No USB Found")
