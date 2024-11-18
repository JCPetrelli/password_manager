import tkinter as tk
from tkinter import messagebox, simpledialog, Listbox
import os
import base64
from dotenv import load_dotenv, set_key, dotenv_values, unset_key
from cryptography.fernet import Fernet
import pyperclip
import random
import string
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import bcrypt

# Load environment variables from .env file
def load_env():
    load_dotenv(override=True)

load_env()

# Master password hash and encryption key (stored securely)
MASTER_PASSWORD_HASH = os.getenv("MASTER_PASSWORD_HASH")

def generate_key(master_password):
    """Generate a Fernet key from the master password using PBKDF2HMAC"""
    salt = os.getenv('SALT')
    if not salt:
        messagebox.showerror("Error", "Salt not found.")
        exit()
    salt = base64.b64decode(salt.encode())
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(master_password.encode())
    return base64.urlsafe_b64encode(key)

def encrypt_password(password, key):
    """Encrypt the password"""
    f = Fernet(key)
    return f.encrypt(password.encode()).decode()

def decrypt_password(encrypted_password, key):
    """Decrypt the password"""
    f = Fernet(key)
    return f.decrypt(encrypted_password.encode()).decode()

def hash_password(password):
    """Hash a password using bcrypt."""
    if password is None:
        raise ValueError("Password cannot be None.")
    if not isinstance(password, str):
        raise TypeError(f"Expected password to be a str, got {type(password)}.")
    
    # Convert password to bytes and hash it
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def check_password(password, hashed):
    """Check if a password matches a hashed password."""
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def save_password(service, password):
    global master_password
    key = generate_key(master_password)
    encrypted_password = encrypt_password(password, key)
    set_key('.env', service, encrypted_password)
    update_password_list()

def get_password(service):
    global master_password
    key = generate_key(master_password)
    encrypted_password = os.getenv(service)
    if encrypted_password:
        try:
            return decrypt_password(encrypted_password, key)
        except Exception:
            messagebox.showerror("Error", "Incorrect master password or corrupted data.")
            return None
    return None

def authenticate():
    global master_password
    master_password = simpledialog.askstring("Authentication", "Enter Master Password:", show='*')
    if master_password is None:
        # User canceled the dialog
        exit()
    if not master_password:
        messagebox.showerror("Error", "Master Password cannot be empty.")
        exit()
    if check_password(master_password, MASTER_PASSWORD_HASH):
        main_screen()
    else:
        messagebox.showerror("Error", "Invalid Master Password")

def add_password():
    service = simpledialog.askstring("Service", "Enter Service Name:")
    if service is None:
        return
    password = simpledialog.askstring("Password", "Enter Password:", show='*')
    if password is None:
        return
    if service and password:
        save_password(service, password)
        messagebox.showinfo("Success", "Password saved successfully")
    else:
        messagebox.showerror("Error", "Service or Password cannot be empty")

def retrieve_password():
    service = password_listbox.get(tk.ACTIVE)
    if not service:
        messagebox.showerror("Error", "No service selected")
        return
    password = get_password(service)
    if password:
        messagebox.showinfo("Password", f"Password for {service}: {password}")
    else:
        messagebox.showerror("Error", "Service not found or incorrect master password")

def copy_to_clipboard():
    service = password_listbox.get(tk.ACTIVE)
    if not service:
        messagebox.showerror("Error", "No service selected")
        return
    password = get_password(service)
    if password:
        pyperclip.copy(password)
        messagebox.showinfo("Copied", f"Password for {service} copied to clipboard")
    else:
        messagebox.showerror("Error", "Service not found or incorrect master password")

def edit_password():
    service = password_listbox.get(tk.ACTIVE)
    if not service:
        messagebox.showerror("Error", "No service selected")
        return
    new_service = simpledialog.askstring("Edit Service", "Enter new Service Name:", initialvalue=service)
    if new_service is None:
        return
    new_password = simpledialog.askstring("Edit Password", "Enter new Password:", show='*')
    if new_password is None:
        return
    if new_service and new_password:
        # Remove the old entry
        unset_key('.env', service)
        # Add the new entry
        save_password(new_service, new_password)
        messagebox.showinfo("Success", "Service updated successfully")
    else:
        messagebox.showerror("Error", "Service or Password cannot be empty")

def update_password_list():
    global password_listbox
    load_env()  # Reload the environment variables
    password_listbox.delete(0, tk.END)
    config = dotenv_values(".env")
    for key in config.keys():
        if key not in ["MASTER_PASSWORD_HASH", "SALT"]:
            password_listbox.insert(tk.END, key)

def generate_random_password():
    """Generate a random password with at least 2 uppercase, 2 special characters, 2 digits, and 20 characters long"""
    uppercases = random.choices(string.ascii_uppercase, k=2)
    special_characters = random.choices(string.punctuation, k=2)
    digits = random.choices(string.digits, k=2)
    remaining_length = 20 - 6
    remaining_chars = random.choices(
        string.ascii_letters + string.digits + string.punctuation, k=remaining_length
    )
    password_list = uppercases + special_characters + digits + remaining_chars
    random.shuffle(password_list)
    password = ''.join(password_list)
    pyperclip.copy(password)
    messagebox.showinfo("Generated Password", "Random password generated and copied to clipboard")

def main_screen():
    global password_listbox

    root = tk.Tk()
    root.title("Password Vault")
    root.geometry("300x400")

    add_btn = tk.Button(root, text="Add Password", command=add_password)
    add_btn.pack(pady=10)

    password_listbox = Listbox(root)
    password_listbox.pack(pady=10, fill=tk.BOTH, expand=True)

    retrieve_btn = tk.Button(root, text="Retrieve Password", command=retrieve_password)
    retrieve_btn.pack(pady=5)

    copy_btn = tk.Button(root, text="Copy to Clipboard", command=copy_to_clipboard)
    copy_btn.pack(pady=5)

    edit_btn = tk.Button(root, text="Edit Password", command=edit_password)
    edit_btn.pack(pady=5)

    generate_btn = tk.Button(root, text="Generate Random Password", command=generate_random_password)
    generate_btn.pack(pady=5)

    update_password_list()

    root.mainloop()

if __name__ == "__main__":
    if MASTER_PASSWORD_HASH is None:
        # First-time setup: ask user to set a master password
        master_password = simpledialog.askstring("Setup", "Set Master Password:", show='*')
        if master_password is None:
            # User canceled the dialog
            exit()
        if not master_password:
            messagebox.showerror("Setup Error", "Master password cannot be empty.")
            exit()
        try:
            salt = os.urandom(16)
            set_key('.env', 'SALT', base64.b64encode(salt).decode())
            MASTER_PASSWORD_HASH = hash_password(master_password)  # Already a string
            set_key('.env', 'MASTER_PASSWORD_HASH', MASTER_PASSWORD_HASH)
            messagebox.showinfo("Success", "Master password set successfully. Please restart the application.")
            exit()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to set master password: {e}")
            exit()
    else:
        authenticate()