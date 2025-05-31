import sys
import os
import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(input_file: str, password: str, output_file: str):
    salt = os.urandom(16)
    iv = os.urandom(16)
    key = derive_key(password, salt)

    with open(input_file, 'rb') as f:
        data = f.read()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()

    with open(output_file, 'wb') as f:
        f.write(salt + iv + encrypted)

    print(f"[+] File encrypted successfully and saved as: {output_file}")

def decrypt_file(input_file: str, password: str, output_file: str):
    with open(input_file, 'rb') as f:
        content = f.read()

    salt = content[:16]
    iv = content[16:32]
    encrypted_data = content[32:]
    key = derive_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()

    with open(output_file, 'wb') as f:
        f.write(data)

    print(f"[+] File decrypted successfully and saved as: {output_file}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: encrypt_tool.exe <encrypt|decrypt> <filename>")
        sys.exit(1)

    mode = sys.argv[1].lower()
    filename = sys.argv[2]

    # Password input with fallback for PowerShell
    try:
        password = getpass.getpass(prompt="Enter password: ")
    except Exception:
        password = input("Enter password: ")

    if mode == "encrypt":
        output_file = filename + ".enc"
        encrypt_file(filename, password, output_file)
    elif mode == "decrypt":
        if not filename.endswith(".enc"):
            print("Error: For decryption, provide an encrypted file ending with '.enc'")
            sys.exit(1)
        output_file = filename.replace(".enc", "_decrypted" + os.path.splitext(filename)[1])
        decrypt_file(filename, password, output_file)
    else:
        print("Invalid mode! Use 'encrypt' or 'decrypt'.")
        sys.exit(1)
