import tkinter as tk
from tkinter import ttk, filedialog, messagebox, Menu
import json
import os
import string
import random
import webbrowser
from cryptography.fernet import Fernet


# the settings for password and key locations
settings_location = 'settings.json'
locations = {"key_location" : " ", "password_location" : " "}

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

# opening the website in browser
def open_browser(item):
    if item.endswith(".com"):
        print(f"clicked {item}")
        webbrowser.open(f"{item}/signin")
    else:
        print(f"clicked {item}.com")
        webbrowser.open(f"{item}.com/signin")

class MainWindowBoot:
    def __init__(self, window) -> None:
        self.window = window
        self.window.title("Sypher Guard")
        self.window.geometry("655x310")

        # ttk configurations 
        self.style = ttk.Style()
        #self.style.configure("TFrame", background="#f5f5f5")
        self.style.configure("TLabel", font=("Arial", 10, 'bold'))
        self.style.configure("TButton", font=("Arial", 10, 'bold'), foreground="Black", background="#f5f5f5")
        # Creating Menubar 
        menubar = Menu(self.window) 
        
        # Adding File Menu and commands 
        files = Menu(menubar, tearoff = 0) 
        menubar.add_cascade(label ='File', menu=files) 
        files.add_command(label ='New File', command=new_files) 
        files.add_command(label ='Backed up Files', command=backed_up_files) 
            
        # Adding Help Menu 
        help_ = Menu(menubar, tearoff = 0) 
        menubar.add_cascade(label ='Help', menu = help_) 
        help_.add_command(label ='Tk Help', command = None) 
        help_.add_command(label ='Demo', command = None) 
        help_.add_separator() 
        help_.add_command(label ='About Tk', command = None) 
        
        # display Menu 
        self.window.config(menu = menubar) 

        ''' generation gui section '''
        self.generating_frame = ttk.Frame(self.window, border=1, relief="solid")
        self.generating_layout()
        self.generating_frame.grid(row=0, column=0, sticky="nw", padx=5, pady=5)

        ''' showing the passwords and saved passwords '''
        self.saved_password_frame = ttk.Frame(self.window, border=1, relief="solid")
        self.saved_password_layout()
        self.saved_password_frame.grid(row=0, column=1, padx=5, pady=5)

    def generating_layout(self):
        generating_frame = tk.Frame(self.generating_frame)

        site_label = ttk.Label(generating_frame, text="Website Name")
        site_label.grid(row=0, column=0, sticky="w", padx=5)
        self.site = tk.StringVar(generating_frame)
        site_entry = ttk.Entry(generating_frame, textvariable=self.site, width=35)
        site_entry.grid(row=1, column=0, padx=0)
        generating_frame.grid(row=0, column=0, padx=5, pady=5)

        checkbox_frame = ttk.Frame(self.generating_frame)
        self.special = tk.BooleanVar(checkbox_frame)
        special_checkbox = ttk.Checkbutton(checkbox_frame, text="Special Characters", variable=self.special)
        special_checkbox.grid(row=0, column=0, sticky="nw", padx=5)
        self.numbers = tk.BooleanVar(checkbox_frame)
        numbers_checkbox = ttk.Checkbutton(checkbox_frame, text="Numbers", variable=self.numbers)
        numbers_checkbox.grid(row=0, column=1, sticky="nw", padx=5)
        self.uppercase = tk.BooleanVar(checkbox_frame)
        uppercase_checkbox = ttk.Checkbutton(checkbox_frame, text="Upper Case", variable=self.uppercase)
        uppercase_checkbox.grid(row=0, column=1, sticky="nw", padx=5)
        self.upper = tk.BooleanVar(checkbox_frame)
        upper_checkbox = ttk.Checkbutton(checkbox_frame, text="Upper Case", variable=self.upper)
        upper_checkbox.grid(row=1, column=0, padx=5, pady=5)
        checkbox_frame.grid(row=1, column=0, pady=5)
        self.lowercase = tk.BooleanVar(checkbox_frame)
        lower_checkbox = ttk.Checkbutton(checkbox_frame, text="Lower Case", variable=self.lowercase)
        lower_checkbox.grid(row=1, column=1, padx=5, pady=5)
        checkbox_frame.grid(row=1, column=0, padx=5, pady=5)
        # length of password and widgets
        length_frame = ttk.Frame(self.generating_frame)
        length_label = ttk.Label(length_frame, text="Length Of Password")
        length_label.grid(row=0, column=0, sticky="w", padx=5)
        self.length = tk.IntVar(length_frame)
        lenght_entry = ttk.Entry(length_frame, width=12, textvariable=self.length)
        lenght_entry.grid(row=0, column=1, padx=5)
        gen_button = ttk.Button(length_frame, text="Generate Password", command=self.generate_password)
        gen_button.grid(row=1, column=0, padx=5, columnspan=2 ,sticky="nesw", pady=5)
        length_frame.grid(row=2, column=0, pady=0)
        
        self.generated_frame = ttk.Frame(self.generating_frame, relief="sunken")
        resulted_frame = ttk.Frame(self.generated_frame)
        resulted_password_label = ttk.Label(resulted_frame, text="Generated Password")
        resulted_password_label.grid(row=0, column=0, pady=5)
        self.generated = tk.StringVar(resulted_frame)
        self.resulted_password = ttk.Entry(resulted_frame, width=34, textvariable=self.generated)
        self.resulted_password.grid(row=1, column=0, padx=5, pady=5)
        save_button = ttk.Button(resulted_frame, text="Save Password", command=self.saving_password)
        save_button.grid(row=2, column=0, pady=0, columnspan=2)
        resulted_frame.grid(row=3, column=0, padx=5, pady=5, sticky="nw")
        self.generated_frame.grid(row=3, column=0, sticky="nw", pady=10)

    def saved_password_layout(self):
        listbox_frame = ttk.Frame(self.saved_password_frame)
        self.saved_passwords = tk.Listbox(listbox_frame, width=40, height=11)
        self.saved_passwords.grid(row=0, column=0, padx=5, pady=5)
        self.saved_passwords.bind("<Double-Button>", self.on_item_selected)
        listbox_frame.grid(row=0, column=0)

        display_frame = tk.Frame(self.saved_password_frame)
        self.show_password = tk.StringVar(display_frame)
        show_password_entry = tk.Entry(display_frame, textvariable=self.show_password, width=40)
        show_password_entry.grid(row=0, column=0)
        display_frame.grid(row=1, column=0, padx=5, pady=5)

        button_frame = ttk.Frame(self.saved_password_frame)
        open_website_button = ttk.Button(button_frame, text="Open Website", command=self.open_site)
        open_website_button.grid(row=1, column=1, padx=5)
        delete_button = ttk.Button(button_frame, text="Delete Password", command=self.delete_site)
        delete_button.grid(row=1, column=2, padx=5)
        button_frame.grid(row=2, column=0)

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
            try:
                for sites in password_data.keys():
                    if sites in seen:
                        return True
                    self.saved_passwords.insert(tk.END, sites)
                return False
            except AttributeError:
                print("No Saved Passwords")
        except FileNotFoundError:
            messagebox.showerror(title="File Not Found", message="Files location not Found Please Enter the External Device")
            self.window.destory()

    def generate_password(self):
        letters = string.ascii_letters
        digi = string.digits
        chara = string.punctuation
        password = []
        # userPasswordLength = int(self.length)
        pool = ""
        if self.special.get():
            pool += chara
        if self.numbers.get():
            pool += digi
        if self.uppercase.get():
            pool += string.ascii_uppercase
        if self.lowercase.get():
            pool += string.ascii_lowercase
        for i in range(int(self.length.get())):
            randomchar = random.choice(pool) 
            password.append(randomchar)
        self.generated.set(''.join(password))
        # return ''.join(password)

        # code to save the password
    
    def saving_password(self):
        print(self.generated.get())
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

        if self.site.get() in json_data:
            messagebox.showerror(title="Site already Exists", message=f"{self.site} already exists in the password file.")
            return
        
        json_data[self.site.get()] = self.generated.get()
        encoded_data = json.dumps(json_data).encode('utf-8')
        encrypted = fernet.encrypt(encoded_data)
        with open(f"{password}", 'wb') as enc_file:
            enc_file.write(encrypted)
        messagebox.showinfo(title="Password Saved", message=f'Password Saved in {os.getcwd()}')
        self.saved_passwords.delete(0, tk.END)
        return MainWindowBoot.updating_listbox(self)

    # creates the code for clicked item
    def on_item_selected(self, event):
        selected_index = self.saved_passwords.curselection()
        if selected_index:  
            index = int(selected_index[0]) 
            self.item = self.saved_passwords.get(index)
            print(self.item)
            website_found = selected_password(self.item)
            if website_found:
                self.show_password.set("\n".join(website_found))
            else:
                print("No Password Set")
        else:
            print("No item selected.")

    def open_site(self):
        open_browser(self.item)

    def delete_site(self):
        #confi_passwords = deleting_password(self.item)
        password_list = reading_password()
        key = reading_key()
        with open(f"{key}", 'rb') as filekey:
            key = filekey.read()
        fernet = Fernet(key)
        confi_passwords = deleting_password(self.item)
        encoded_data = json.dumps(confi_passwords).encode('utf-8')
        encrypted = fernet.encrypt(encoded_data)
        with open(f"{password_list}", 'wb') as enc_file:
            enc_file.write(encrypted)
        self.saved_passwords.delete(tk.ACTIVE)
        self.saved_passwords.after(1)
        self.show_password.set("")
        
''' Done this Nice '''
def new_files():
    key_location = filedialog.askdirectory(initialdir=os.listdir())
    key = Fernet.generate_key()
    with open(f"{key_location}/keyfile.key", 'wb') as keyfile:
        keyfile.write(key)
    password_location = filedialog.askdirectory(initialdir=os.listdir())
    settings_file = {"key_location": f"{key_location}/keyfile.key", "password_location": f"{password_location}/password.json"}
    with open(settings_location, 'w') as settings_file_writing:
        json.dump(settings_file, settings_file_writing)
    MainWindowBoot(sypher)

''' this needs to be recoded mainly the update listbox section '''
def backed_up_files():
    print("Backed")
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
    backed_window = MainWindowBoot(sypher)
    backed_window.updating_listbox()

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

# deleting passwords
def deleting_password(item):
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
    print(password_data)
    return password_data


if __name__ == '__main__':
    sypher = tk.Tk()
    if os.path.isfile(settings_location):
        main_window = MainWindowBoot(sypher)
        main_window.updating_listbox()
    else:
        messagebox.showinfo("No Files Found", message="No Password Or Key Files Found Refer to Files in the Menu Bar!")
        MainWindowBoot(sypher)
    sypher.mainloop()


