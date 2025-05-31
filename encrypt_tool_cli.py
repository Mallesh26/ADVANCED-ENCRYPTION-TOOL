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

def decrypt_file(input_file: str, password: str, output_file: str):
    try:
        with open(input_file, 'rb') as f:
            content = f.read()

        salt = content[:16]
        iv = content[16:32]
        signature = content[-32:]
        encrypted_data = content[32:-32]

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

    except Exception as e:
        print(f"[-] Error during decryption: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description="AES-256 File Encryptor/Decryptor with HMAC")
    parser.add_argument('command', choices=['encrypt', 'decrypt'], help="encrypt or decrypt a file")
    parser.add_argument('input_file', help="Path to input file")
    parser.add_argument('-o', '--output', help="Output file path (optional)")
    args = parser.parse_args()

    password = getpass.getpass("Enter password: ")

    if args.command == 'encrypt':
        output_file = args.output if args.output else args.input_file + '.enc'
        encrypt_file(args.input_file, password, output_file)
    else:
        output_file = args.output if args.output else args.input_file + '.dec'
        decrypt_file(args.input_file, password, output_file)

if __name__ == "__main__":
    main()
