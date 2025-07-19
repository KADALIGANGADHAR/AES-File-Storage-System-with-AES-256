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

**```sudo apt update  && sudo apt upgrade```**

**```sudo apt install python3-venv -y```**

<img width="1920" height="892" alt="image" src="https://github.com/user-attachments/assets/39a0ccb9-cdd1-4a26-a6d2-d35c54aacab3" />

### 🔹Step 2: Create Project Folder & Virtual Environment
