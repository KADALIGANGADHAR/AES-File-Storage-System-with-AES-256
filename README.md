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



