# 🔐 Secure File Storage System with AES-256

This project is a CLI-based encryption and decryption system using **AES-256 (CBC Mode)** with **SHA-256 hash verification**. It securely stores files locally with `.enc` extension and verifies file integrity during decryption.

---

## 🎯 Objective

To securely encrypt and decrypt files using **AES-256** with:
- Password-derived key
- Random IV
- Metadata storage (hash, time, filename)
- Hash integrity check during decryption

---

## 🧰 Tools Used

- Python 3
- cryptography module
- hashlib, json, os
- Command Line Interface (CLI)
- Tested on Kali Linux

---

## 🔧 Step-by-Step Installation & Setup

### 🔹 Step 1: Install Python Virtual Environment

- **```sudo apt update  && sudo apt upgrade```**
- **```sudo apt install python3-venv -y```**

<img width="1920" height="892" alt="image" src="https://github.com/user-attachments/assets/39a0ccb9-cdd1-4a26-a6d2-d35c54aacab3" />

### 🔹Step 2: Create Project Folder & Virtual Environment

- **```mkdir ~/AES_File_Storage```**
- **```cd ~/AES_File_Storage```**
- **```python3 -m venv aesenv```**
- **```source aesenv/bin/activate```**

<img width="1920" height="892" alt="image" src="https://github.com/user-attachments/assets/5119a42b-ca6e-4195-ba2e-c6fb48e078c7" />

### 🔹 Step 3: Install Required Python Library
- **```pip install cryptography```**
<img width="1920" height="678" alt="image" src="https://github.com/user-attachments/assets/2e1687e9-41af-4027-884f-bfe60da0b25f" />

### 🔹 Step 4: Create Python File
- **```touch aes_secure_storage.py```**
- **```nano aes_secure_storage.py```**
<img width="1920" height="243" alt="image" src="https://github.com/user-attachments/assets/e6b084ec-70fa-4b65-81cb-4330362e85d0" />
<img width="1920" height="892" alt="image" src="https://github.com/user-attachments/assets/a79f1631-0583-4fef-9fe8-f0bfeceb09c2" />
<img width="1920" height="892" alt="image" src="https://github.com/user-attachments/assets/cdfcf8b9-e187-46c5-878e-fc3e13cd78f0" />
<img width="1920" height="892" alt="image" src="https://github.com/user-attachments/assets/663e84b8-6ceb-40e8-9aba-30ee87e267e4" />
<img width="1920" height="892" alt="image" src="https://github.com/user-attachments/assets/71e3438d-7481-4cdf-be5d-58408a296395" />
<img width="1920" height="892" alt="image" src="https://github.com/user-attachments/assets/5b82b6d9-eb0d-4777-85e6-c2b9c963545e" />
<img width="1920" height="892" alt="image" src="https://github.com/user-attachments/assets/9dce7bfd-b2a3-4762-a428-3699ca51b2ff" />
<img width="1920" height="892" alt="image" src="https://github.com/user-attachments/assets/a1df0798-c84b-492b-bfc8-a8549ac0934d" />

bash
```**
import os
import json
import base64
import hashlib
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import sys

PASSWORD = b'my_secure_password_123'
KEY = hashlib.sha256(PASSWORD).digest()  # 256-bit key

def pad(data):
    padder = padding.PKCS7(128).padder()
    return padder.update(data) + padder.finalize()

def unpad(data):
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(data) + unpadder.finalize()

def encrypt_file(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()

    original_hash = hashlib.sha256(data).hexdigest()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(pad(data)) + encryptor.finalize()

    encrypted_file = file_path + ".enc"
    with open(encrypted_file, 'wb') as f:
        f.write(iv + encrypted_data)

    metadata = {
        "original_name": os.path.basename(file_path),
        "encrypted_name": os.path.basename(encrypted_file),
        "timestamp": datetime.now().isoformat(),
        "sha256": original_hash
    }

    with open(encrypted_file + ".meta.json", 'w') as meta_file:
        json.dump(metadata, meta_file, indent=4)

    print(f"✅ Encrypted and saved as: {encrypted_file}")
    print(f"📄 Metadata saved as: {encrypted_file}.meta.json")

def decrypt_file(enc_path):
    with open(enc_path, 'rb') as f:
        content = f.read()
    iv = content[:16]
    encrypted_data = content[16:]

    cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    decrypted_data = unpad(decrypted_data)

    meta_path = enc_path + ".meta.json"
    with open(meta_path, 'r') as meta_file:
        metadata = json.load(meta_file)

    hash_check = hashlib.sha256(decrypted_data).hexdigest()

    if hash_check != metadata['sha256']:
        print("❌ File hash mismatch. File may be tampered.")
        return

    output_file = "decrypted_" + metadata['original_name']
    with open(output_file, 'wb') as f:
        f.write(decrypted_data)

    print(f"✅ File decrypted and saved as: {output_file}")

def main():
    if len(sys.argv) != 3:
        print("Usage:")
        print("  Encrypt: python3 aes_secure_storage.py enc <file_path>")
        print("  Decrypt: python3 aes_secure_storage.py dec <encrypted_file>")
        return

    command = sys.argv[1]
    path = sys.argv[2]

    if not os.path.exists(path):
        print("❌ File not found.")
        return

    if command == "enc":
        encrypt_file(path)
    elif command == "dec":
        decrypt_file(path)
    else:
        print("❌ Invalid command. Use 'enc' or 'dec'.")

if __name__ == "__main__":
    main()
```

-  *Paste this code inside the editor (nano), then press Ctrl + X, then Y, then Enter to save:*
-  
### 🔹 Step 5: Create a Sample File to Test

- **```echo "This is a secret message." > secret.txt```**
<img width="1657" height="172" alt="image" src="https://github.com/user-attachments/assets/f8f4efed-37af-4cf4-a2cf-313a27fd88bf" />



## 🔐 AES File Encryption and Decryption (Without & With  Password)

### 🔐 *Method 1: AES Without Password*

### 🔒 Encrypt a File
- **```python3 aes_secure_storage.py enc secret.txt```**
<img width="1920" height="250" alt="image" src="https://github.com/user-attachments/assets/987277ad-8aba-46d3-81ef-b331fe21badf" />

### 🔓 Decrypt a File
- **```python3 aes_secure_storage.py dec secret.txt.enc```**
<img width="1920" height="292" alt="image" src="https://github.com/user-attachments/assets/e7b5df11-af0f-4d83-b0c1-efe34eb7551d" />

### 🔐*Method 2: AES With Password*

**1.Open the file:**
- **```nano aes_secure_storage.py```**
<img width="1254" height="130" alt="image" src="https://github.com/user-attachments/assets/73e3768a-5602-4333-ad97-e9389e1fa02e" />

**2.Add this function to get AES key from password:**

 - **``` def get_key_from_password():
    password = getpass.getpass("🔑 Enter password: ")
    return hashlib.sha256(password.encode()).digest()```**
   
#### *Paste this anywhere before main() or if __name__ == '__main__'::*
<img width="1920" height="892" alt="image" src="https://github.com/user-attachments/assets/c1e0f610-42a4-4c2c-a229-c03b4dec25b1" />







