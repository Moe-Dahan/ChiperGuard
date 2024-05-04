# ChiperGuard
CipherGuard is a secure and user-friendly password manager application developed in Python using the Tkinter GUI library. It provides a convenient way to generate, store, and manage passwords securely.
CipherGuard
CipherGuard is a secure and user-friendly password manager application developed in Python using the Tkinter GUI library. It provides a convenient way to generate, store, and manage passwords securely.

Table of Contents
Features
Installation
Usage
Screenshots
Contributing
License
Features
Password Generation
Generate strong and random passwords with customizable options:
Length of the password
Inclusion of special characters, numbers, uppercase, and lowercase letters
Password Storage
Save generated passwords along with corresponding website names for easy retrieval.
Passwords are securely encrypted using the Fernet encryption scheme from the cryptography library.
Password Management
View and manage saved passwords:
Copy passwords to clipboard for usage.
Delete passwords when they are no longer needed.
Backup and Restore
Backup password data to external files for safekeeping.
Restore password data from backup files if necessary.
Installation
Clone the repository:
bash
Copy code
git clone https://github.com/your-username/CipherGuard.git
Navigate to the project directory:
bash
Copy code
cd CipherGuard
Install the required dependencies:
bash
Copy code
pip install -r requirements.txt
Usage
Run the application:
bash
Copy code
python main.py
On the first run, the application will prompt you to create new settings or select backup files if the settings file is missing.
Once settings are configured, the main window will display options to generate passwords, save passwords, and view/delete existing passwords.
Screenshots
(Add relevant screenshots here)

Contributing
Contributions are welcome! If you have any ideas, suggestions, or improvements, feel free to open an issue or create a pull request.

License
This project is licensed under the MIT License. See the LICENSE file for details.

Acknowledgments
Python Tkinter Documentation: https://docs.python.org/3/library/tkinter.html
Cryptography library: https://cryptography.io/en/latest/fernet/
Icons made by Iconfinder: (Add proper attribution if required)
