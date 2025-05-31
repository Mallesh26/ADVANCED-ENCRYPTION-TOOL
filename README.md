# ADVANCED-ENCRYPTION-TOOL
*COMPny*:CODTECH IT SOLUTIONS
*NAME*:Mudavath Mallesh Nayak
*INTERN ID*:CT04DL263
*DOMAIN*:Cyber Security & Ethical Hacking
*DURATION*:4 weeks
*MENTOR*: NEELA SANTOSH KUMAR
## DESCRIPTION ##
AES-256 File Encryptor/Decryptor with HMAC
  The goal of this task was to develop a secure file encryption and decryption tool in Python using AES-256 encryption in CBC mode combined with HMAC for message integrity verification. The tool allows users to safely encrypt sensitive files with a password-derived cryptographic key and ensures data confidentiality and authenticity during both encryption and decryption processes.

Key Features:

AES-256 Encryption: Utilizes AES with a 256-bit key in CBC mode for strong symmetric encryption.

Password-Based Key Derivation: Derives encryption keys securely from user passwords using PBKDF2 with SHA-256, salt, and 100,000 iterations to resist brute-force attacks.

PKCS7 Padding: Applies PKCS7 padding to plaintext before encryption to handle arbitrary file sizes.

HMAC Verification: Incorporates HMAC with SHA-256 to authenticate the encrypted data and prevent tampering.

Command-Line Interface: Supports easy command-line operations for encrypting and decrypting files with optional output paths.

Secure Random Initialization Vectors and Salts: Uses cryptographically secure random values for salt and IV to strengthen encryption.

Usage:

Encrypt a file:

nginx
Copy code
python aes_encryptor.py encrypt input_file.txt -o output_file.enc
Decrypt a file:

nginx
Copy code
python aes_encryptor.py decrypt output_file.enc -o decrypted_file.txt
Outcome:

This tool provides a reliable way to protect files with strong encryption and verify their integrity, meeting the requirements for secure data storage and transmission. It demonstrates practical understanding of cryptography concepts and Python security libraries.

##OUTPUT##
 
![Image](https://github.com/user-attachments/assets/f5ad7ddb-6c0a-455a-928f-5dc4ac5119cc)
