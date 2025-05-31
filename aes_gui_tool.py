import os
import tkinter as tk
from tkinter import filedialog, messagebox
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

def encrypt_file(input_file: str, password: str):
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

    output_file = input_file + ".enc"
    with open(output_file, 'wb') as f:
        f.write(salt + iv + encrypted)

    return output_file

def decrypt_file(input_file: str, password: str):
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

    output_file = input_file.replace(".enc", ".dec")
    with open(output_file, 'wb') as f:
        f.write(data)

    return output_file

# GUI Setup
def browse_file():
    file_path.set(filedialog.askopenfilename())

def handle_encrypt():
    try:
        out = encrypt_file(file_path.get(), password.get())
        messagebox.showinfo("Success", f"Encrypted:\n{out}")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def handle_decrypt():
    try:
        out = decrypt_file(file_path.get(), password.get())
        messagebox.showinfo("Success", f"Decrypted:\n{out}")
    except Exception as e:
        messagebox.showerror("Error", str(e))

app = tk.Tk()
app.title("AES-256 Encryption Tool")
app.geometry("400x200")

file_path = tk.StringVar()
password = tk.StringVar()

tk.Label(app, text="Select File:").pack()
tk.Entry(app, textvariable=file_path, width=40).pack()
tk.Button(app, text="Browse", command=browse_file).pack(pady=5)

tk.Label(app, text="Password:").pack()
tk.Entry(app, textvariable=password, show="*").pack()

tk.Button(app, text="Encrypt", command=handle_encrypt, bg="green", fg="white").pack(pady=5)
tk.Button(app, text="Decrypt", command=handle_decrypt, bg="blue", fg="white").pack()

app.mainloop()
