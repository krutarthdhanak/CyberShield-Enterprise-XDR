from usb.usb_scanner import scan_usb

results = scan_usb()

for file in results:
    print(file)
