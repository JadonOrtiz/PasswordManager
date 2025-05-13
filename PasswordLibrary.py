"""
TEAM PROJECT
CS2520 SP2025
JADON ORTIZ, DYLAN MONGE

This file handles the two-way encryption and decryption of the passwords in the general library.
It uses a combination of encryption and salting to secure the passwords.

Encrypted passwords are stored in: passwords.json
Random salt is stored in: salt.txt
"""

import json
import os
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac

PASSWORD_FILE = "passwords.json"
SALT_FILE = "salt.txt"
ITERATIONS = 200000

def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a secure encryption key from the master password."""
    key = pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        ITERATIONS
    )
    return urlsafe_b64encode(key)

def generate_salt() -> bytes:
    """Generate a secure, random salt."""
    return os.urandom(16)

def get_salt() -> bytes:
    """Retrieve or generate a salt for key derivation."""
    if not os.path.exists(SALT_FILE):
        salt = generate_salt()
        with open(SALT_FILE, "wb") as file:
            file.write(salt)
    else:
        with open(SALT_FILE, "rb") as file:
            salt = file.read()
    return salt

def encrypt_data(data: dict, key: bytes) -> bytes:
    """Encrypt the password data."""
    fernet = Fernet(key)
    return fernet.encrypt(json.dumps(data).encode('utf-8'))

def decrypt_data(encrypted_data: bytes, key: bytes) -> dict:
    """Decrypt the password data."""
    fernet = Fernet(key)
    return json.loads(fernet.decrypt(encrypted_data).decode('utf-8'))

def save_passwords(data: dict, key: bytes):
    """Save encrypted password data to file."""
    encrypted_data = encrypt_data(data, key)
    with open(PASSWORD_FILE, "wb") as file:
        file.write(encrypted_data)

def load_passwords(key: bytes) -> dict:
    """Load and decrypt password data from file."""
    if not os.path.exists(PASSWORD_FILE):
        return {}
    with open(PASSWORD_FILE, "rb") as file:
        encrypted_data = file.read()
    return decrypt_data(encrypted_data, key)

def add_password(service_name: str, email: str, password: str, key: bytes):
    """Add a new password entry."""
    passwords = load_passwords(key)
    passwords[service_name] = {"email": email, "password": password}
    save_passwords(passwords, key)
    print(f"Password for '{service_name}' added successfully.")

def delete_password(service_name: str, key: bytes):
    """Delete a password entry by service name."""
    passwords = load_passwords(key)

    if service_name in passwords:
        del passwords[service_name]
        save_passwords(passwords, key)
        print(f"Password for '{service_name}' has been deleted.")
    else:
        print(f"No entry found for service '{service_name}'.")

def modify_password(service_name: str, key: bytes):
    """Modify the email or password for a given service."""
    passwords = load_passwords(key)

    if service_name not in passwords:
        print(f"No entry found for service '{service_name}'.")
        return

    print("\nWhat would you like to modify?")
    print("1. Update Email")
    print("2. Update Password")
    choice = input("Enter your choice: ")

    if choice == "1":
        new_email = input("Enter the new email: ")
        passwords[service_name]["email"] = new_email
        print(f"Email for '{service_name}' updated successfully.")
    elif choice == "2":
        new_password = input("Enter the new password: ")
        passwords[service_name]["password"] = new_password
        print(f"Password for '{service_name}' updated successfully.")
    else:
        print("Invalid choice. Returning to main menu.")

    save_passwords(passwords, key)

def view_passwords(key: bytes):
    """View all stored passwords."""
    passwords = load_passwords(key)
    if not passwords:
        print("No passwords stored.")
        return
    for service, info in passwords.items():
        print(f"\nService: {service}\n  Email: {info['email']}\n  Password: {info['password']}")

