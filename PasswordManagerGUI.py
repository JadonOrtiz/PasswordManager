import tkinter as tk
from tkinter import messagebox, simpledialog
import PasswordLibrary
from PasswordLibrary import derive_key, get_salt, view_passwords, add_password, delete_password, modify_password
import bcrypt
import os

from PasswordManager import save_hashed_password

ADMIN_PASSWORD_FILE = "admin_password.txt"
MAX_ATTEMPTS = 5

# Global variable to track login attempts
attempts = 0
key = None

def load_hashed_password() -> bytes:
    if os.path.exists(ADMIN_PASSWORD_FILE):
        with open(ADMIN_PASSWORD_FILE, "rb") as file:
            return file.read()
    return None

def check_password(hashed: bytes, password: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed)

def manager_password(master_password: str) -> bytes:
    """Authenticate the admin password and return the derived encryption key."""
    stored_hash = load_hashed_password()

    if stored_hash is None:
        # First-time setup
        hashed = bcrypt.hashpw(master_password.encode('utf-8'), bcrypt.gensalt())
        with open(ADMIN_PASSWORD_FILE, "wb") as file:
            file.write(hashed)
        messagebox.showinfo("Setup", "Admin password set successfully.")
        return derive_key(master_password, get_salt())

    # Check the entered password against the stored hash
    if check_password(stored_hash, master_password):
        return derive_key(master_password, get_salt())
    else:
        return None

def on_login():
    """Handle the login button click."""
    global attempts, key
    password = password_entry.get()

    # Check the password
    key = manager_password(password)
    if key:
        messagebox.showinfo("Success", "Access granted!")
        root.destroy()  # Close the login window
        open_dashboard(key)  # Open the dashboard
    else:
        attempts += 1
        if attempts >= MAX_ATTEMPTS:
            messagebox.showerror("Locked Out", "Too many failed attempts. Exiting...")
            root.destroy()
        else:
            messagebox.showerror("Error", f"Incorrect password. Attempt {attempts} of {MAX_ATTEMPTS}.")

def reset_admin_password(key: bytes):
    """Reset the admin password and re-encrypt the password library."""
    # Confirm the current password
    current_password = simpledialog.askstring("Reset Password", "Enter your current admin password:", show="*")
    stored_hash = load_hashed_password()

    if not check_password(stored_hash, current_password):
        messagebox.showerror("Error", "Incorrect current password.")
        return

    # Get the new password
    new_password = simpledialog.askstring("Reset Password", "Enter your new admin password:", show="*")
    confirm_password = simpledialog.askstring("Reset Password", "Confirm your new admin password:", show="*")

    if not new_password or not confirm_password:
        messagebox.showerror("Error", "Password fields cannot be empty.")
        return

    if new_password != confirm_password:
        messagebox.showerror("Error", "Passwords do not match.")
        return

    # Update the password
    salt = get_salt()
    new_key = derive_key(new_password, salt)
    passwords = PasswordLibrary.load_passwords(key)
    PasswordLibrary.save_passwords(passwords, new_key)

    # Save the new admin password hash
    new_hashed = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
    save_hashed_password(new_hashed)

    messagebox.showinfo("Success", "Admin password has been updated successfully!")

def open_dashboard(key: bytes):
    """Create the main dashboard window."""
    dashboard = tk.Tk()
    dashboard.title("Password Manager Dashboard")
    dashboard.geometry("500x350")

    # Dashboard Title
    tk.Label(dashboard, text="Password Manager", font=("Arial", 18, "bold")).pack(pady=20)

    # Menu Buttons
    tk.Button(dashboard, text="View Stored Passwords", width=30, command=lambda: view_passwords_gui(key)).pack(pady=5)
    tk.Button(dashboard, text="Add New Password", width=30, command=lambda: add_password_gui(key)).pack(pady=5)
    tk.Button(dashboard, text="Delete Password", width=30, command=lambda: delete_password_gui(key)).pack(pady=5)
    tk.Button(dashboard, text="Modify Password/Email", width=30, command=lambda: modify_password_gui(key)).pack(pady=5)
    tk.Button(dashboard, text="Reset Admin Password", width=30, command=lambda: reset_admin_password(key)).pack(pady=5)
    tk.Button(dashboard, text="Exit", width=30, command=dashboard.destroy).pack(pady=20)

    dashboard.mainloop()


def view_passwords_gui(key: bytes):
    """Display all stored passwords with toggleable visibility."""
    passwords = PasswordLibrary.load_passwords(key)
    if not passwords:
        messagebox.showinfo("No Passwords", "No passwords stored.")
        return

    view_window = tk.Toplevel()
    view_window.title("Stored Passwords")
    view_window.geometry("600x500")

    # Add a title
    tk.Label(view_window, text="Stored Passwords", font=("Arial", 16, "bold")).pack(pady=10)

    # Create a frame to hold the password entries
    frame = tk.Frame(view_window)
    frame.pack(pady=10)

    for service, info in passwords.items():
        # Service Name
        service_label = tk.Label(frame, text=f"Service: {service}", font=("Arial", 12, "bold"))
        service_label.grid(row=len(frame.winfo_children()) // 4, column=0, sticky="w", padx=10, pady=5)

        # Email
        email_label = tk.Label(frame, text=f"Email: {info['email']}")
        email_label.grid(row=len(frame.winfo_children()) // 4, column=1, sticky="w", padx=10, pady=5)

        # Password (Hidden by default)
        password_var = tk.StringVar(value="•" * len(info["password"]))
        password_label = tk.Label(frame, textvariable=password_var)
        password_label.grid(row=len(frame.winfo_children()) // 4, column=2, sticky="w", padx=10, pady=5)

        # Create the toggle button using a factory function to avoid late binding issues
        def make_toggle_button(pw_var, actual_pw):
            return tk.Button(frame, text="Show", width=6,
                             command=lambda: toggle_password(pw_var, actual_pw))

        # Create and place the button
        toggle_button = make_toggle_button(password_var, info["password"])
        toggle_button.grid(row=len(frame.winfo_children()) // 4 - 1, column=3, padx=5, pady=5)

        # Toggle function (defined outside the loop to prevent late binding)
        def toggle_password(pw_var, actual_pw):
            if pw_var.get() == "•" * len(actual_pw):
                pw_var.set(actual_pw)
            else:
                pw_var.set("•" * len(actual_pw))

    # Add a close button
    tk.Button(view_window, text="Close", command=view_window.destroy).pack(pady=20)

    view_window.mainloop()

def add_password_gui(key: bytes):
    """Prompt the user to add a new password."""
    service = simpledialog.askstring("Add Password", "Enter service name:")
    email = simpledialog.askstring("Add Password", "Enter associated email:")
    password = simpledialog.askstring("Add Password", "Enter the password:")

    if service and email and password:
        add_password(service, email, password, key)
        messagebox.showinfo("Success", f"Password for '{service}' added successfully.")

def delete_password_gui(key: bytes):
    """Prompt the user to delete a password."""
    service = simpledialog.askstring("Delete Password", "Enter the service name to delete:")

    if service:
        delete_password(service, key)

def modify_password_gui(key: bytes):
    """Prompt the user to modify an email or password."""
    service = simpledialog.askstring("Modify Password", "Enter the service name to modify:")

    if service:
        passwords = PasswordLibrary.load_passwords(key)

        if service not in passwords:
            messagebox.showerror("Error", f"No entry found for service '{service}'.")
            return

        choice = simpledialog.askinteger("Modify Password", "Enter 1 to modify the email, 2 to modify the password:")

        if choice == 1:
            new_email = simpledialog.askstring("Update Email", "Enter the new email:")
            passwords[service]["email"] = new_email
            messagebox.showinfo("Success", f"Email for '{service}' updated successfully.")
        elif choice == 2:
            new_password = simpledialog.askstring("Update Password", "Enter the new password:")
            passwords[service]["password"] = new_password
            messagebox.showinfo("Success", f"Password for '{service}' updated successfully.")
        else:
            messagebox.showerror("Error", "Invalid choice.")

        PasswordLibrary.save_passwords(passwords, key)

# Create the main login window
root = tk.Tk()
root.title("Password Manager Login")
root.geometry("300x150")

tk.Label(root, text="Enter Admin Password").pack(pady=10)
password_entry = tk.Entry(root, show="*", width=30)
password_entry.pack(pady=5)
tk.Button(root, text="Login", command=on_login).pack(pady=10)

root.mainloop()


