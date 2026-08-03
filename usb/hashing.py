import hashlib


def sha256_hash(file_path):
    """
    Generate SHA-256 hash of a file.
    """

    sha256 = hashlib.sha256()

    try:
        with open(file_path, "rb") as file:

            while True:

                data = file.read(4096)

                if not data:
                    break

                sha256.update(data)

        return sha256.hexdigest()

    except Exception as e:
        return f"HASH_ERROR: {e}"
