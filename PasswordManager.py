"""
TEAM PROJECT
CS2520 SP2025
JADON ORTIZ, DYLAN MONGE

This program currently lets the user set a master 'admin password', which then
gives them access to the console menu. From the console menu, the user can view
password entries. Currently, each entry has the fields SERVICE, EMAIL, and PASSWORD.

This file handles the hashing/storage of the admin password, which is stored in:
admin_password.txt
"""

import bcrypt
import os
from PasswordLibrary import derive_key, get_salt, view_passwords, add_password, delete_password, modify_password

ADMIN_PASSWORD_FILE = "admin_password.txt"
MAX_ATTEMPTS = 5

def hash_password(password: str) -> bytes:
    """Hash a password using bcrypt."""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed

def check_password(hashed: bytes, password: str) -> bool:
    """Check a password against a given hash."""
    return bcrypt.checkpw(password.encode('utf-8'), hashed)

def save_hashed_password(hashed: bytes):
    """Save the hashed password to a file."""
    with open(ADMIN_PASSWORD_FILE, "wb") as file:
        file.write(hashed)

def load_hashed_password() -> bytes:
    """Load the hashed password from a file."""
    if os.path.exists(ADMIN_PASSWORD_FILE):
        with open(ADMIN_PASSWORD_FILE, "rb") as file:
            return file.read()
    return None

def manager_password() -> bytes:
    """Authenticate the admin with a secure hashed password."""
    stored_hash = load_hashed_password()

    # First-time setup
    if stored_hash is None:
        print("No admin password found. Please set a new password.")
        new_password = input("Enter a new admin password: ")
        hashed = hash_password(new_password)
        save_hashed_password(hashed)
        print("Admin password set successfully.")
        return derive_key(new_password, get_salt())

    # Authenticate existing password
    for attempt in range(MAX_ATTEMPTS):
        password = input("Enter the admin password: ")
        if check_password(stored_hash, password):
            print("Access granted.")
            return derive_key(password, get_salt())
        else:
            print(f"Wrong password. Attempt {attempt + 1} of {MAX_ATTEMPTS}.")

    print("Locked out due to too many failed attempts.")
    return None

def manager():
    key = manager_password()
    if key:
        while True:
            print("\nPassword Manager Menu:")
            print("1. View Stored Passwords")
            print("2. Add New Password")
            print("3. Delete Password")
            print("4. Modify Existing Password/Email")
            print("0. Exit")
            choice = input("Enter your choice: ")

            if choice == "1":
                view_passwords(key)
            elif choice == "2":
                service = input("Enter service name: ")
                email = input("Enter associated email: ")
                password = input("Enter the password: ")
                add_password(service, email, password, key)
            elif choice == "3":
                service = input("Enter the service name to delete: ")
                delete_password(service, key)
            elif choice == "4":
                service = input("Enter the service name to modify: ")
                modify_password(service, key)
            elif choice == "0":
                print("Exiting the program.")
                break
            else:
                print("Invalid choice. Please try again.")

if __name__ == "__main__":
    manager()

# def changeManagerPassword():
#   exit = 1
#   while exit != 0:
#     print("changing manager password")
#     exit = int(input("Enter 0 to exit: "))
#   return manager()
