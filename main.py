import tkinter as tk
from tkinter import messagebox, filedialog
import random
import string
import json
from cryptography.fernet import Fernet
import os


# the settings for password and key locations
settings_location = 'settings.json'
locations = {"key_location" : " ", "password_location" : " "}

# sets the new file on start up function
def new_settings():
    key_location = filedialog.askdirectory(initialdir=os.listdir())
    key = Fernet.generate_key()
    with open(f"{key_location}/keyfile.key", 'wb') as keyfile:
        keyfile.write(key)
    password_location = filedialog.askdirectory(initialdir=os.listdir())
    settings_file = {"key_location": f"{key_location}/keyfile.key", "password_location": f"{password_location}/password.json"}
    with open(settings_location, 'w') as settings_file_writing:
        json.dump(settings_file, settings_file_writing)
    MainWindow(root)

# this is for the backup function
def selecting_backup():
    key_location = filedialog.askopenfilename(initialdir=os.listdir(), filetypes=[("Key file", "*.key")])
    if key_location.endswith(".key"):
        messagebox.showinfo(title="Key File", message="Key file Loaded Successfully!")
    else:
        messagebox.showerror(title="Error Loading", message="Please make sure its a .key file!")
    password_location = filedialog.askopenfilename(initialdir=os.listdir(), filetypes=[("Password file", "*.json")])
    if password_location.endswith(".json"):
        messagebox.showinfo(title="Password File", message="Password file Loaded Successfully!")
    else:
        messagebox.showerror(title="Error Loading", message="Please make sure its a .json file!")
    settings_file = {"key_location": f"{key_location}", "password_location": f"{password_location}"}
    with open(settings_location, 'w') as settings_file_writing:
        json.dump(settings_file, settings_file_writing)
    locations.update(settings_file)
    backed_window = MainWindow(root)
    backed_window.updating_listbox()

# reads the key location
def reading_key():
    with open(settings_location, 'r') as settings_file:
        settings = json.load(settings_file)
    selected_key_location = settings['key_location']
    return selected_key_location

# reads the password location
def reading_password():
    with open(settings_location, 'r') as settings_file:
        settings = json.load(settings_file)
    selected_password_location = settings['password_location']
    return selected_password_location

# working with the passwords class
class WorkingPasswords:
    def __init__(self, length, speical, numbers, upper, lower, site, saved_passwords) -> None:
        self.length = length
        self.speical = speical
        self.numbers = numbers
        self.upper = upper
        self.lower = lower
        self.site = site
        self.saved_passwords = saved_passwords

    # generating the passwords 
    def generate_password(self):
        letters = string.ascii_letters
        digi = string.digits
        chara = string.punctuation
        password = []
        userPasswordLength = int(self.length)
        pool = ""
        if self.speical:
            pool += chara
        if self.numbers:
            pool += digi
        if self.upper:
            pool += string.ascii_uppercase
        if self.lower:
            pool += string.ascii_lowercase
        for i in range(userPasswordLength):
            randomchar = random.choice(pool) 
            password.append(randomchar)
        return ''.join(password)
    
    # code to save the password
    def saving_password(self, generated):
        print(generated)
        key = reading_key()
        password = reading_password()

        with open(f"{key}", 'rb') as filekey:
            key = filekey.read()
        fernet = Fernet(key)

        try:
            with open(f"{password}", 'rb') as enc_file:
                encrypted = enc_file.read()
            decrypted = fernet.decrypt(encrypted)
            decoded_data = decrypted.decode('utf-8')
            json_data = json.loads(decoded_data)
        except FileNotFoundError:
            json_data = {}

        if self.site in json_data:
            messagebox.showerror(title="Site already Exists", message=f"{self.site} already exists in the password file.")
            return
        
        json_data[self.site] = generated
        encoded_data = json.dumps(json_data).encode('utf-8')
        encrypted = fernet.encrypt(encoded_data)
        with open(f"{password}", 'wb') as enc_file:
            enc_file.write(encrypted)
        messagebox.showinfo(title="Password Saved", message=f'Password Saved in {os.getcwd()}')
        self.saved_passwords.delete(0, tk.END)
        return MainWindow.updating_listbox(self)
    
    # showing the selected password
    def showing_password(password, item):
        website_found = WorkingPasswords.selected_password(item=item)
        # password = tk.StringVar(frame_returned_password)
        # password_entry = tk.Entry(frame_returned_password, textvariable=password, width=30)
        # password_entry.grid(row=0, column=0)
        if website_found:
            return ("\n".join(website_found))
        else:
            print("No Password Set")
        #return password
    
    # returns the selected password from the drop box
    def selected_password(item):
        password_list = reading_password()
        key_list = reading_key()
        with open(f"{key_list}", 'rb') as filekey:
            key = filekey.read()
        fernet = Fernet(key)
        with open(f"{password_list}", 'rb') as enc_file:
            encrypted = enc_file.read()
        decrypted = fernet.decrypt(encrypted)
        decoded_data = decrypted.decode('utf-8')
        password_data = json.loads(decoded_data)
        websites_found = []
        if item in password_data:
            websites_found.append(f"{password_data[item]}")
            return websites_found
    
    # opening the website in browser
    def open_browser(item):
        import webbrowser
        webbrowser.open(f"{item}")

    # deleting passwords
    def deleting_password(self, item):
        password_list = reading_password()
        key_list = reading_key()
        with open(f"{key_list}", 'rb') as filekey:
            key = filekey.read()
        fernet = Fernet(key)
        with open(f"{password_list}", 'rb') as enc_file:
            encrypted = enc_file.read()
        decrypted = fernet.decrypt(encrypted)
        decoded_data = decrypted.decode('utf-8')
        password_data = json.loads(decoded_data)
        if item in password_data:
            del password_data[item]
        return password_data

# main window for the program and code to call other class    
class MainWindow:
    def __init__(self, window) -> None:
        self.window = window
        self.window.geometry("355x480")
        self.window.resizable(False, False)
        self.window.title("CipherGuard")
        self.window.iconbitmap("icons/iconfinder-securityprotectlockshield35-4021451_113107.ico") # just for windows
        
        self.layout_section()

    # main layout of the gui
    def layout_section(self):
        ''' main frame for topside starts here'''
        encrypting_frame = tk.Frame(self.window, border=1, relief="solid", width=320, height=400)
        ''' website entry from here '''
        site_frame = tk.Frame(encrypting_frame)
        site_label = tk.Label(site_frame, text="Website Name ", font=("Arial", 10, 'bold'))
        site_label.grid(row=0, column=0)
        self.site = tk.StringVar(site_frame)
        site_entry = tk.Entry(site_frame, textvariable=self.site, width=35)
        site_entry.grid(row=0, column=1)
        site_frame.grid(row=0, column=0, pady=5, padx=5)
        ''' checkbox from here '''
        checkbox_frame = tk.Frame(encrypting_frame)
        self.special = tk.BooleanVar(checkbox_frame)
        special_checkbox = tk.Checkbutton(checkbox_frame, text="Special Characters", font=("Arial", 10, 'bold'), variable=self.special)
        special_checkbox.grid(row=0, column=0, sticky="nw")
        self.numbers = tk.BooleanVar(checkbox_frame)
        numbers_checkbox = tk.Checkbutton(checkbox_frame, text="Numbers", font=("Arial", 10, 'bold'), variable=self.numbers)
        numbers_checkbox.grid(row=0, column=1, sticky="nw")
        self.upper = tk.BooleanVar(checkbox_frame)
        upper_checkbox = tk.Checkbutton(checkbox_frame, text="Upper Case", font=("Arial", 10, 'bold'), variable=self.upper)
        upper_checkbox.grid(row=1, column=0)
        self.lower = tk.BooleanVar(checkbox_frame)
        lower_checkbox = tk.Checkbutton(checkbox_frame, text="Lower Case", font=("Arial", 10, 'bold'), variable=self.lower)
        lower_checkbox.grid(row=1, column=1)
        checkbox_frame.grid(row=1, column=0, pady=5, padx=5)
        ''' length from here '''
        length_frame = tk.Frame(encrypting_frame)
        self.lengh = tk.IntVar(length_frame)
        lenght_label = tk.Label(length_frame, text="Length Of Password", font=("Arial", 10, 'bold'))
        lenght_label.grid(row=0, column=0, sticky="nw")
        lenght_entry = tk.Entry(length_frame, width=5, font=("Arial", 10), textvariable=self.lengh)
        lenght_entry.grid(row=0, column=1)
        gen_button = tk.Button(length_frame, text="Generate Password", font=("Arial", 10, 'bold'), background="Green", fg="White", command=self.gene_pass)
        gen_button.grid(row=0, column=2, padx=5)
        length_frame.grid(row=2, column=0, sticky="nw", padx=5, pady=5)
        ''' the resulted generated password from here '''
        resulted_password_frame = tk.Frame(encrypting_frame, border=1, relief="solid")
        self.generated = tk.StringVar(resulted_password_frame)
        self.resulted_password = tk.Entry(resulted_password_frame, width=45, font=("Arial", 10), textvariable=self.generated)
        self.resulted_password.grid(row=0, column=0, padx=5, pady=5)
        save_button = tk.Button(resulted_password_frame, text="Save Password", font=("Arial", 10, 'bold'), command=self.saving_passwords)
        save_button.grid(row=1, column=0)
        resulted_password_frame.grid(row=3, column=0, pady=5, padx=5)

        encrypting_frame.grid(row=0, column=0, sticky="nw", padx=5, pady=5)
        ''' top half main frame stops here '''

        ''' showing the saved Passwords '''
        saved_passwords_frame = tk.Frame(self.window, border=1, relief="solid", width=342, height=250)

        self.saved_passwords = tk.Listbox(saved_passwords_frame, width=56, height=15)
        self.saved_passwords.grid(row=0, column=0)
        self.saved_passwords.bind("<Double-Button>", self.on_item_selected)

        saved_passwords_frame.grid(row=1, column=0, sticky="nw", padx=5, pady=5)

    # generating function call
    def gene_pass(self):
        site = self.site.get() 
        length = self.lengh.get() 
        speical = self.special.get() 
        numbers = self.numbers.get()
        upper = self.upper.get() 
        lower = self.lower.get() 
        self.password = WorkingPasswords(length, speical, numbers, upper, lower, site, self.saved_passwords)
        self.generated_password = self.password.generate_password() 
        self.generated.set(self.generated_password) 

    # saving the generated password function
    def saving_passwords(self):
        self.password.saving_password(self.generated_password)

    # creates the code for clicked item
    def on_item_selected(self, event):
        selected_index = self.saved_passwords.curselection()
        if selected_index:  
            index = int(selected_index[0]) 
            item = self.saved_passwords.get(index)  
            new_window_password_view(item, self.saved_passwords)  
        else:
            print("No item selected.")

    # updates the password list
    def updating_listbox(self):
        seen = set()
        selected_key = reading_key()
        selected_password = reading_password()
        try:
            with open(f"{selected_key}", 'rb') as filekey:
                key = filekey.read()
            fernet = Fernet(key)
            with open(f"{selected_password}", 'rb') as enc_file:
                encrypted = enc_file.read()
            decrypted = fernet.decrypt(encrypted)
            decoded_data = decrypted.decode('utf-8')
            password_data = json.loads(decoded_data)
            for sites in password_data.keys():
                if sites in seen:
                    return True
                self.saved_passwords.insert(tk.END, sites)
            return False
        except FileNotFoundError:
            messagebox.showerror(title="File Not Found", message="Files location not Found Please Enter the External Device")
            self.window.destory()

# popup window to open or check the passowrd    
def new_window_password_view(item, saved_passwords):
    new_window = tk.Toplevel(root)
    new_window.iconbitmap("icons/iconfinder-securityprotectlockshield35-4021451_113107.ico")
    new_window.geometry("375x90")
    new_window.resizable(False, False)
    new_window.config(background="Gray")

    frame_returned_password = tk.Frame(new_window)
    password = tk.StringVar(frame_returned_password)
    password_entry = tk.Entry(frame_returned_password, textvariable=password, width=60)
    password_entry.grid(row=0, column=0)
    frame_returned_password.grid(row=0, column=0, padx=5, pady=10)

    buttons_frame = tk.Frame(new_window, background="Gray")
    show_password_button = tk.Button(buttons_frame, text="Show Password", command=lambda: show_password(password, item), font=("Arial", 10, 'bold'))
    show_password_button.grid(row=1, column=0, padx=5)
    open_website_button = tk.Button(buttons_frame, text="Open Website", command=lambda: open_browser_site(item), font=("Arial", 10, 'bold'))
    open_website_button.grid(row=1, column=1, padx=5)
    delete_button = tk.Button(buttons_frame, text="Delete Password", command=lambda: deleting_selected_password(item, saved_passwords), font=("Arial", 10, 'bold'))
    delete_button.grid(row=1, column=2, padx=5)
    buttons_frame.grid(row=1, column=0, padx=5, pady=5)
    new_window.mainloop()

def show_password(password, item):
    show_password = WorkingPasswords.showing_password(password, item)
    password.set(show_password)

def open_browser_site(item):
    WorkingPasswords.open_browser(item)

def deleting_selected_password(item, saved_passwords):
    password_list = reading_password()
    key = reading_key()
    with open(f"{key}", 'rb') as filekey:
        key = filekey.read()
    fernet = Fernet(key)
    working_passwords_instance = WorkingPasswords.deleting_password(self=WorkingPasswords, item=item)
    encoded_data = json.dumps(working_passwords_instance).encode('utf-8')
    encrypted = fernet.encrypt(encoded_data)
    with open(f"{password_list}", 'wb') as enc_file:
        enc_file.write(encrypted)
    saved_passwords.delete(tk.ACTIVE)
    MainWindow.updating_listbox(MainWindow)
    
if __name__ == "__main__":
    root = tk.Tk()
    if os.path.isfile(settings_location):
        main_window = MainWindow(root)
        main_window.updating_listbox()
    else:
        create_new = messagebox.askyesno(title="create new files", message="Would You like to create new File?")
        if create_new:
            new_settings()
        else:
            selecting_backup()
    root.mainloop()