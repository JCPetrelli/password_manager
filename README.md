
# Password Manager

A simple password manager built with Python and `tkinter` for managing and securely storing your passwords. This tool encrypts your passwords, protects them with a master password, and allows you to manage your password vault with ease.

---

## Features

- **Secure Storage**: Passwords are encrypted using Fernet encryption and stored in a `.env` file.
- **Master Password Protection**: A hashed master password is required to access the vault.
- **Password Management**: Add, retrieve, copy, edit, or delete passwords for various services.
- **Random Password Generation**: Generate a secure random password with uppercase letters, digits, and special characters.
- **Clipboard Integration**: Copy passwords to your clipboard for quick access.
- **Graphical Interface**: Easy-to-use interface built with `tkinter`.

---

## How It Works

1. **Master Password Setup**:
   - On the first run, you'll set a master password. This password will be hashed using bcrypt and stored in the `.env` file.

2. **Password Encryption**:
   - Passwords are encrypted using a key derived from the master password and stored securely.

3. **User Interaction**:
   - Use the GUI to add, retrieve, edit, or copy passwords. The vault is updated dynamically.

4. **Random Password Generator**:
   - Generate a 20-character random password with customizable complexity.

---

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/yourusername/password-manager.git
   cd password-manager
   ```

2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Ensure the following Python libraries are installed:
   - `tkinter`
   - `bcrypt`
   - `cryptography`
   - `dotenv`
   - `pyperclip`

4. Run the script:
   ```bash
   python vault.py
   ```

---

## Usage

1. **First Time Setup**:
   - Set a master password on the first run.
   - An encryption key will be generated and saved in the `.env` file.

2. **Add a Password**:
   - Click "Add Password" and provide the service name and password.

3. **Retrieve a Password**:
   - Select a service from the list and click "Retrieve Password."

4. **Edit a Password**:
   - Select a service and click "Edit Password" to update its name or password.

5. **Generate a Random Password**:
   - Click "Generate Random Password" to create a secure password and copy it to your clipboard.

6. **Copy to Clipboard**:
   - Select a service and click "Copy to Clipboard" to copy its password.

---

## Security Considerations

- **`.env` File**:
  - Passwords are encrypted but stored in the `.env` file. Ensure this file is protected and not exposed to unauthorized access.

- **Encryption Key**:
  - The encryption key is stored in the `.env` file. Losing this file will result in losing access to stored passwords.

- **Master Password**:
  - Keep your master password safe. If it’s forgotten, passwords cannot be recovered.

---

## Limitations

- Designed as a learning tool and not recommended for production use.
- Lacks advanced security features like breach alerts or recovery options.
- Not suitable for managing a large number of passwords or sharing credentials securely.

---

## Future Improvements

- Use a secure database for password storage instead of a `.env` file.
- Add support for exporting and importing password data.
- Implement multi-factor authentication for added security.
- Modernize the GUI with libraries like PyQt or customtkinter.

---

## Contributing

Contributions are welcome! Feel free to submit issues, feature requests, or pull requests to improve the project.

---

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

---

## Acknowledgements

- Built using Python and libraries like `tkinter`, `bcrypt`, and `cryptography`.
- Inspired by the need to learn more about encryption and password management.

---

