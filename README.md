# Tajnik - Secure Password Manager

Tajnik is a simple yet secure command-line password manager that helps you store and manage your passwords with ease. Using robust symmetric encryption, Tajnik ensures your sensitive information is kept secure and private.

## Features

- Secure storage of passwords with symmetric encryption
- Command-line interface for easy use and automation
- Support for adding, retrieving, and updating passwords
- Automated HMAC checks to ensure data integrity

## Installation

To run Tajnik, you will need Python 3.6+ installed on your system.

1. Clone the repository or download the `tajnik.py` and `tajnik.sh` files to your local machine.
2. Ensure `tajnik.sh` is executable by running:
   ```bash
   chmod +x tajnik.sh
   ```

3. You can now use ./tajnik.sh to interact with the Tajnik password manager

## Usage

To initialize Tajnik with a master password:
```bash
   ./tajnik.sh init <YourMasterPassword>
```
To store a new password:
```bash
    ./tajnik.sh put <YourMasterPassword> <Website> <Password>
```
To retrieve a stored password
```bash
    ./tajnik.sh get <YourMasterPassword> <Website>
```

## Security

Tajnik uses AES for encryption, SHA-256 for HMAC, and PBKDF2 for key derivation, ensuring a high level of security for your stored passwords.

