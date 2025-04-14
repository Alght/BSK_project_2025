import os
import psutil
import tkinter as tk
from tkinter import filedialog
import logging
import threading
import time
from tkinter import messagebox
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP

logging.basicConfig(level=logging.DEBUG)
class encryption_app:

    def __init__(self, root):
        self.root = root   
        self.message = tk.StringVar()
        self.key_path_message = tk.StringVar()
        self.key_path_message.set('No key detected')   

        # variables for cryptography
        self.pem_files = []             
        self.pin_var = tk.StringVar()
        self.file_path = ''
        self.key_path = None
        self.private_key = None

        self.public_key = None

        self.public_key_path = None       
        # app GUI  
        self.root.title("Cryptography app")     
        self.root.minsize(200,100)
        self.root.maxsize(400, 300)
        self.pin_entry = tk.Entry(root, textvariable=self.pin_var, font=("calibre", 10, "normal"), show="*")
        self.submit_pin = tk.Button(root, text="Submit", command=self.submit_pin)
        self.choose_pdf_btn = tk.Button(root, text="Choose PDF", command=self.choose_pdf)
        self.sign_pdf_btn = tk.Button(root, text="Sign", command=self.sign_pdf)
        self.verify_btn = tk.Button(root, text="Verify", command=self.verify_pdf)
        self.choose_pub_key_btn = tk.Button(root, text="Choose public key", command=self.choose_pub_key)
        
        self.label = tk.Label(root, textvariable=self.message)
        self.key_label = tk.Label(root, textvariable=self.key_path_message) 
        self.key_label.grid(row=1, column=2)
        self.pin_entry.grid(row=2, column=2)
        self.submit_pin.grid(row=2, column=3)        
        self.choose_pdf_btn.grid(row=4, column=2)
        self.sign_pdf_btn.grid(row=5, column=2)
        self.verify_btn.grid(row=6, column=2)
        self.choose_pub_key_btn.grid(row=7, column=2)
        self.label.grid(row=9, column=2)


        # USB port 
        self.detected_drives = set(
            self.get_usb_drives()
        )  
        self.monitor_thread = threading.Thread(target=self.monitor_usb, daemon=True)
        self.monitor_thread.start()

    def get_usb_drives(self):
        # check for new drive
        usb_drives = []
        for partition in psutil.disk_partitions():
            if "removable" in partition.opts:
                usb_drives.append(partition.mountpoint)
        return usb_drives

    def monitor_usb(self):
        # monitor usb port
        while True:
            time.sleep(2)  
            current_drives = set(self.get_usb_drives())

            new_drives = current_drives - self.detected_drives
            if new_drives:
                for drive in new_drives:
                    self.root.after(0, self.on_usb_inserted, drive)

            self.detected_drives = current_drives

    def on_usb_inserted(self, drive_path):
        # os.system(
        #     f"xdg-open {drive_path}" if os.name == "posix" else f"start {drive_path}"
        # )
        logging.debug('Pendrive detected')            
        self.pem_files = self.find_pem_files(drive_path)
        if not self.pem_files:
            logging.debug('No key detected on pendrive')            
            self.message.set('No key detected on pendrive!')  
            return     
        self.key_path = self.pem_files[0]

        self.key_path_message.set(self.key_path)
        
    def find_pem_files(self, directory):
        pem_files = []
        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith(".pem"):
                    pem_files.append(os.path.join(root, file))
        return pem_files   
     
    def submit_pin(self):
        pin = self.pin_var.get().strip()
        if not pin:
            logging.debug("PIN cannot be empty!")
            self.message.set('PIN cannot be empty!')
            return
        elif len(pin) < 4:
            logging.debug("PIN is too short!")
            self.message.set('PIN is too short!')
            return

        if self.key_path is None:
            logging.debug('No key detected!')            
            self.message.set('No key detected!')
            
        
        self.private_key = self.load_and_decrypt_private_key(self.key_path, pin)
        logging.debug(f'Private key: {self.private_key}') 
        if self.private_key is None:
            return           
        self.pin_var.set("") 
        self.message.set('Key ready!')

    def choose_pdf(self):
        logging.debug("choose_pdf")
        file_path = tk.filedialog.askopenfilename(filetypes=[('Allowed Types', '*.pdf')], initialdir="./")
        if not file_path:
            logging.debug("No file selected.")
            self.message.set('No file selected.')

            return
        logging.debug(f"File selected: {file_path}")
        self.file_path = file_path

    def choose_pub_key(self):
        logging.debug("choose_pub_key")
        file_path = tk.filedialog.askopenfilename(filetypes=[('Allowed Types', '*.pem')], initialdir="./")
        if not file_path:
            logging.debug("No file selected.")
            self.message.set('No file selected.')
            return
        logging.debug(f"File selected: {file_path}")
        self.public_key_path = file_path


        with open(file_path, "rb") as f:
            self.public_key = f.read()
            self.private_key = RSA.import_key(self.public_key)
            logging.debug(f"Public key: {self.public_key}")
            self.message.set(f"Public key: {self.public_key_path}")


    """decryption and encryption"""        
    def derive_aes_key(self, pin):
        hasher = SHA256.new(pin.encode())
        return hasher.digest()  
             
    def decrypt_private_key(self, encrypted_data, aes_key):
        iv = encrypted_data[:16]
        encrypted_private_key = encrypted_data[16:]

        cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)

        decrypted_padded = cipher_aes.decrypt(encrypted_private_key)

        padding_length = decrypted_padded[-1]
        padding_length = decrypted_padded[-1]
        if padding_length < 1 or padding_length > 16:
            raise ValueError("Invalid padding")
        private_key = decrypted_padded[:-padding_length]

        return private_key

    def load_and_decrypt_private_key(self, file_path, pin):
        logging.debug('load_and_decrypt_private_key')            

        aes_key = self.derive_aes_key(pin)

        if file_path is None:
            logging.debug("No key path")
            return


        with open(file_path, "rb") as f:
            encrypted_data = f.read()

        decrypted_private_key = self.decrypt_private_key(encrypted_data, aes_key)

        private_key = RSA.import_key(decrypted_private_key)
        logging.debug("Private key decrypted successfully!")
        logging.debug(private_key)

        return private_key
    
# sign and verify

    def sign_pdf(self):
        logging.debug("sign_pdf")
        if self.private_key is None:
            logging.debug('No private key detected!')            
            self.message.set('No private key detected!')
            return
        if not self.file_path or len(self.file_path) == 0:
            logging.debug('No PDF!')            
            return

    def verify_pdf(self):
        logging.debug("verify_pdf")
        if self.public_key is None:
            logging.debug('No public key detected!')            
            self.message.set('No public key detected!')
            return
        if not self.file_path or len(self.file_path) == 0:
            logging.debug('No PDF!')            
            return
        
# Run the function
if __name__ == "__main__":
  print("App start")
  root = tk.Tk()
  app = encryption_app(root)
  root.mainloop()

