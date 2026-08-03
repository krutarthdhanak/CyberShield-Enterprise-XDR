import os

DANGEROUS_EXTENSIONS = {
    ".exe",
    ".bat",
    ".cmd",
    ".vbs",
    ".ps1",
    ".js",
    ".scr",
    ".com"
}


def scan_folder(folder_path):
    """
    Scan all files in the given folder.
    Returns a list of file information.
    """

    results = []

    if not os.path.exists(folder_path):
        print(f"Folder not found: {folder_path}")
        return results

    for root, dirs, files in os.walk(folder_path):

        for file in files:

            full_path = os.path.join(root, file)

            size = os.path.getsize(full_path)

            extension = os.path.splitext(file)[1].lower()

            if extension in DANGEROUS_EXTENSIONS:
                risk = "HIGH"
            elif extension in [".zip", ".rar"]:
                risk = "MEDIUM"
            else:
                risk = "LOW"

            results.append({
                "name": file,
                "path": full_path,
                "size": size,
                "extension": extension,
                "risk": risk
            })

    return results
