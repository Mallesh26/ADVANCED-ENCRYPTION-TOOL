import argparse
import getpass
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding, hmac
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
    try:
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

        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(salt + iv + encrypted)
        signature = h.finalize()

        with open(output_file, 'wb') as f:
            f.write(salt + iv + encrypted + signature)

        print(f"[+] File encrypted successfully and saved as: {output_file}")
    except FileNotFoundError:
        print("[!] Input file not found.")
    except Exception as e:
        print(f"[!] Encryption failed: {e}")

def decrypt_file(input_file: str, password: str, output_file: str):
    try:
        with open(input_file, 'rb') as f:
            content = f.read()

        if len(content) < 64:
            raise ValueError("Input file is too short or corrupted.")

        salt = content[:16]
        iv = content[16:32]
        encrypted_data = content[32:-32]
        signature = content[-32:]

        key = derive_key(password, salt)

        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(salt + iv + encrypted_data)
        h.verify(signature)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()

        with open(output_file, 'wb') as f:
            f.write(data)

        print(f"[+] File decrypted successfully and saved as: {output_file}")
    except FileNotFoundError:
        print("[!] Input file not found.")
    except ValueError as ve:
        print(f"[!] Error: {ve}")
    except hmac.InvalidSignature:
        print("[!] Decryption failed: File has been tampered with or wrong password.")
    except Exception as e:
        print(f"[!] Decryption error: {e}")

def main():
    parser = argparse.ArgumentParser(description="AES File Encryptor/Decryptor with Error Handling")
    parser.add_argument('command', choices=['encrypt', 'decrypt'], help="Operation to perform")
    parser.add_argument('input_file', help="Input file path")
    parser.add_argument('-o', '--output', help="Output file path (optional)")

    args = parser.parse_args()

    if not os.path.isfile(args.input_file):
        print(f"[!] Error: Input file '{args.input_file}' not found.")
        return

    password = getpass.getpass("Enter password: ")

    if args.command == 'encrypt':
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("[!] Passwords do not match. Exiting.")
            return
        output_file = args.output if args.output else args.input_file + '.enc'
        encrypt_file(args.input_file, password, output_file)
    else:
        output_file = args.output if args.output else args.input_file + '_decrypted'
        decrypt_file(args.input_file, password, output_file)

if __name__ == "__main__":
    main()
