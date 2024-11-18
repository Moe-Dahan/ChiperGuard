# THINGS TO KEEP IN MIND BEFORE USING THIS SOFTWARE
If You Lose The Encryption/Decryption Key All Passwords will be lost for ever.
If you want to upload your password.json file to the cloud for backup you can, DO NOT UPLOAD YOU KEY ALONG WITH IT to the cloud.
Keep your key file backed up to a USB or External Device (External hard drive or Mobile Device etc...),
To maximize security.

# CipherGuard - Secure Password Manager

**CipherGuard** is a Python-based password manager built using the Tkinter library. It allows you to generate, store, and manage encrypted passwords securely. The application supports backing up and restoring key and password files, ensuring your data is protected.

## Features
- **Password Generation**: Create strong, customizable passwords with options for:
  - Uppercase letters
  - Lowercase letters
  - Numbers
  - Special characters
- **Encrypted Password Storage**: Passwords are stored securely using AES encryption with `Fernet` (from the `cryptography` library).
- **Keyfile and Password Backup**: Easily back up your encryption key and password file to external storage. You can later restore your data from these backups.
- **Password Management**: 
  - View saved passwords
  - Delete passwords
  - Directly open websites associated with saved passwords
- **User-friendly Interface**: The GUI is intuitive, built with `Tkinter` and `ttk`, making it easy for anyone to use.

# Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/Moe-Dahan/cipherguard.git
   cd cipherguard
   
2. Install required dependencies: You need to install the dependencies listed in the requirements.txt file
   ```bash
   pip install -r requirements.txt

# Run The Script
3. To Run the script simply do
    ```bash
    python main.py
  Another option is to use pyinstaller to create a bootable application, (for linux you just need to remove/comment the # iconbitmap lines
  
# Usage
First-Time Setup
When running the app for the first time, you'll be prompted to create new encryption files.
Choose directories to store your keyfile and password file.
Backing Up Files
You can back up your keyfile and password file by selecting the "Backup" option in the menu.

# Restoring Files
If you have backed up your files, you can restore them using the "Restore" option in the app, allowing you to access your saved passwords again.

# Password Generation
Enter a website name.
Customize the password by choosing the length and whether to include special characters, numbers, uppercase, or lowercase letters.
Save the generated password securely.
Security
Your passwords are encrypted using AES encryption provided by the cryptography library.
The encryption key is stored in a separate keyfile, adding an extra layer of security.

# Contribution
Contributions are welcome! Please open an issue or submit a pull request if you have suggestions or improvements.![Screenshot from 2024-11-18 18-39-35](https://github.com/user-attachments/assets/57b23c96-e385-4402-aa0c-9c509e0d591e)
![Screenshot from 2024-11-18 18-39-16](https://github.com/user-attachments/assets/cef36a04-05f4-4043-b929-5e470b9fce74)
![Screenshot from 2024-11-18 18-38-56](https://github.com/user-attachments/assets/49610da4-6204-450f-b230-c1a3373c24db)



