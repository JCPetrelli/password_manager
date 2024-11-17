import tkinter as tk
from tkinter import messagebox, simpledialog, Listbox
import os
import bcrypt
import base64
from dotenv import load_dotenv, set_key, dotenv_values, unset_key
from cryptography.fernet import Fernet
import pyperclip
import random
import string

# Load environment variables from .env file
def load_env():
    load_dotenv(override=True)

load_env()

# Master password hash and encryption key (stored securely)
MASTER_PASSWORD_HASH = os.getenv("MASTER_PASSWORD_HASH")
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")

def generate_key(master_password):
    """Generate a Fernet key from the master password"""
    key = bcrypt.kdf(
        password=master_password.encode(),
        salt=b'some_salt',  # Use a secure random salt
        desired_key_bytes=32,
        rounds=100
    )
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
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt)

def check_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed)

def save_password(service, password):
    key = generate_key(master_password)
    encrypted_password = encrypt_password(password, key)
    set_key('.env', service, encrypted_password)
    update_password_list()

def get_password(service):
    key = generate_key(master_password)
    encrypted_password = os.getenv(service)
    if encrypted_password:
        return decrypt_password(encrypted_password, key)
    return None

def authenticate():
    global master_password
    master_password = simpledialog.askstring("Authentication", "Enter Master Password:", show='*')
    if check_password(master_password, MASTER_PASSWORD_HASH.encode()):
        main_screen()
    else:
        messagebox.showerror("Error", "Invalid Master Password")

def add_password():
    service = simpledialog.askstring("Service", "Enter Service Name:")
    password = simpledialog.askstring("Password", "Enter Password:", show='*')
    if service and password:
        save_password(service, password)
        messagebox.showinfo("Success", "Password saved successfully")
    else:
        messagebox.showerror("Error", "Service or Password cannot be empty")

def retrieve_password():
    service = password_listbox.get(tk.ACTIVE)
    password = get_password(service)
    if password:
        messagebox.showinfo("Password", f"Password for {service}: {password}")
    else:
        messagebox.showerror("Error", "Service not found")

def copy_to_clipboard():
    service = password_listbox.get(tk.ACTIVE)
    password = get_password(service)
    if password:
        pyperclip.copy(password)
        messagebox.showinfo("Copied", f"Password for {service} copied to clipboard")

def edit_password():
    service = password_listbox.get(tk.ACTIVE)
    new_service = simpledialog.askstring("Edit Service", "Enter new Service Name:", initialvalue=service)
    new_password = simpledialog.askstring("Edit Password", "Enter new Password:", show='*')
    if new_service and new_password:
        # Remove the old entry
        unset_key('.env', service)
        # Add the new entry
        save_password(new_service, new_password)
        messagebox.showinfo("Success", "Service updated successfully")
    else:
        messagebox.showerror("Error", "Service or Password cannot be empty")

def update_password_list():
    load_env()  # Reload the environment variables
    password_listbox.delete(0, tk.END)
    config = dotenv_values(".env")
    for key in config.keys():
        if key not in ["MASTER_PASSWORD_HASH", "ENCRYPTION_KEY"]:
            password_listbox.insert(tk.END, key)

def generate_random_password():
    """Generate a random password with at least 2 uppercase, 2 special characters, 2 digits, and 20 characters long"""
    uppercases = random.choices(string.ascii_uppercase, k=2)
    special_characters = random.choices(string.punctuation, k=2)
    digits = random.choices(string.digits, k=2)
    remaining_length = 20 - 6
    remaining_chars = random.choices(string.ascii_letters + string.digits + string.punctuation, k=remaining_length)
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
        # First time setup: ask user to set a master password
        master_password = simpledialog.askstring("Setup", "Set Master Password:", show='*')
        MASTER_PASSWORD_HASH = hash_password(master_password).decode()
        set_key('.env', 'MASTER_PASSWORD_HASH', MASTER_PASSWORD_HASH)
        # Generate and store encryption key
        ENCRYPTION_KEY = base64.urlsafe_b64encode(Fernet.generate_key()).decode()
        set_key('.env', 'ENCRYPTION_KEY', ENCRYPTION_KEY)
        messagebox.showinfo("Setup", "Master Password set successfully")
    else:
        authenticate()