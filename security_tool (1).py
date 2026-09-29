#!/usr/bin/env python3
"""
security_tool.py

Small security toolkit for the ETTCS801 Cryptography and Network Security
project.

Files:
    student_record.txt
    student_record.enc
    student_record_decrypted.txt
    integrity_hash.txt

The Fernet encryption key is stored OUTSIDE the project repository, one
folder above the project directory.
"""

import hashlib
import os
import sys

from cryptography.fernet import Fernet, InvalidToken


# ---------------------------------------------------------------------------
# File locations
# ---------------------------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(BASE_DIR)

KEY_FILE = os.path.join(PARENT_DIR, "encryption.key")
INPUT_FILE = os.path.join(BASE_DIR, "student_record.txt")
ENCRYPTED_FILE = os.path.join(BASE_DIR, "student_record.enc")
DECRYPTED_FILE = os.path.join(BASE_DIR, "student_record_decrypted.txt")
HASH_FILE = os.path.join(BASE_DIR, "integrity_hash.txt")


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def generate_key():
    """Generate a Fernet key outside the repository."""
    if os.path.exists(KEY_FILE):
        print(f"Key already exists: {KEY_FILE}")
        print("No new key was generated.")
        return

    key = Fernet.generate_key()

    try:
        with open(KEY_FILE, "wb") as file:
            file.write(key)
    except OSError as error:
        print(f"Error: Could not save encryption key: {error}")
        return

    print("Encryption key generated successfully.")
    print(f"Key location: {KEY_FILE}")
    print("Keep this key outside the GitHub repository.")


def load_key():
    """Load the Fernet key from outside the repository."""
    if not os.path.exists(KEY_FILE):
        raise FileNotFoundError(
            f"Encryption key not found: {KEY_FILE}\n"
            "Generate it with: python security_tool.py key"
        )

    try:
        with open(KEY_FILE, "rb") as file:
            key = file.read().strip()
        return Fernet(key)
    except (OSError, ValueError) as error:
        raise ValueError(f"Invalid encryption key: {error}") from error


def sha256_file(filename):
    """Return the SHA-256 hexadecimal digest of a file."""
    if not os.path.exists(filename):
        raise FileNotFoundError(f"File not found: {filename}")

    digest = hashlib.sha256()

    with open(filename, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            digest.update(chunk)

    return digest.hexdigest()


# ---------------------------------------------------------------------------
# Encryption
# ---------------------------------------------------------------------------

def encrypt_file():
    """Encrypt the sample student record."""
    if not os.path.exists(INPUT_FILE):
        raise FileNotFoundError(f"Input file not found: {INPUT_FILE}")

    cipher = load_key()

    with open(INPUT_FILE, "rb") as file:
        plaintext = file.read()

    encrypted = cipher.encrypt(plaintext)

    with open(ENCRYPTED_FILE, "wb") as file:
        file.write(encrypted)

    print("Encryption successful.")
    print(f"Input : {INPUT_FILE}")
    print(f"Output: {ENCRYPTED_FILE}")


# ---------------------------------------------------------------------------
# Decryption and verification
# ---------------------------------------------------------------------------

def decrypt_file():
    """Decrypt the encrypted record and compare it with the original."""
    if not os.path.exists(ENCRYPTED_FILE):
        raise FileNotFoundError(
            f"Encrypted file not found: {ENCRYPTED_FILE}"
        )

    if not os.path.exists(INPUT_FILE):
        raise FileNotFoundError(f"Original file not found: {INPUT_FILE}")

    cipher = load_key()

    with open(ENCRYPTED_FILE, "rb") as file:
        encrypted = file.read()

    try:
        decrypted = cipher.decrypt(encrypted)
    except InvalidToken as error:
        raise ValueError(
            "Decryption failed: invalid key or corrupted encrypted data."
        ) from error

    with open(DECRYPTED_FILE, "wb") as file:
        file.write(decrypted)

    with open(INPUT_FILE, "rb") as file:
        original = file.read()

    if decrypted == original:
        print("Decryption successful.")
        print("Verification successful: decrypted content matches the original.")
    else:
        print("Decryption completed, but verification FAILED.")
        print("The decrypted content does not match the original.")

    print(f"Decrypted output: {DECRYPTED_FILE}")


# ---------------------------------------------------------------------------
# Integrity baseline
# ---------------------------------------------------------------------------

def save_hash():
    """Calculate and save the current SHA-256 as the integrity baseline."""
    digest = sha256_file(INPUT_FILE)

    with open(HASH_FILE, "w", encoding="utf-8") as file:
        file.write(digest + "\n")

    print("SHA-256 calculated successfully.")
    print(f"Current SHA-256: {digest}")
    print(f"Baseline saved to: {HASH_FILE}")


def verify_hash():
    """Compare the current SHA-256 with the saved baseline."""
    if not os.path.exists(HASH_FILE):
        raise FileNotFoundError(
            "Integrity baseline not found. Run: python security_tool.py hash"
        )

    current = sha256_file(INPUT_FILE)

    with open(HASH_FILE, "r", encoding="utf-8") as file:
        saved = file.read().strip()

    print(f"Saved SHA-256 : {saved}")
    print(f"Current SHA-256: {current}")

    if current == saved:
        print("Integrity check PASSED: no change detected.")
    else:
        print("Integrity check FAILED: file change detected.")


# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------

def show_help():
    print("""
Usage:
    python security_tool.py key
    python security_tool.py encrypt
    python security_tool.py decrypt
    python security_tool.py hash
    python security_tool.py verify
    python security_tool.py help

Commands:
    key       Generate the Fernet encryption key outside the repository.
    encrypt   Encrypt student_record.txt.
    decrypt   Decrypt and verify student_record.enc.
    hash      Calculate and save the original SHA-256 baseline.
    verify    Compare the current SHA-256 with the saved baseline.
    help      Display this help message.
""")


# ---------------------------------------------------------------------------
# Main command-line interface
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) != 2:
        print("Error: Please provide one command.")
        show_help()
        return 1

    command = sys.argv[1].lower()

    try:
        if command == "key":
            generate_key()
        elif command == "encrypt":
            encrypt_file()
        elif command == "decrypt":
            decrypt_file()
        elif command == "hash":
            save_hash()
        elif command == "verify":
            verify_hash()
        elif command == "help":
            show_help()
        else:
            print(f"Error: Unknown command '{command}'.")
            show_help()
            return 1

    except (FileNotFoundError, OSError, ValueError) as error:
        print(f"Error: {error}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())