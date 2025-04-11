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
       
        # app GUI  
        self.root.title("Cryptography app")     
        self.root.minsize(200,100)
        self.root.maxsize(300, 200)
        self.pin_entry = tk.Entry(root, textvariable=self.pin_var, font=("calibre", 10, "normal"), show="*")
        self.submit_pin = tk.Button(root, text="Submit", command=self.submit_pin)
        self.choose_pdf_btn = tk.Button(root, text="Choose PDF", command=self.choose_pdf)
        self.encrypt_btn = tk.Button(root, text="Encrypt", command=self.encrypt_pdf)
        self.decrypt_btn = tk.Button(root, text="Decrypt", command=self.decrypt_pdf)
        
        self.label = tk.Label(root, textvariable=self.message)
        self.key_label = tk.Label(root, textvariable=self.key_path_message) 
        self.key_label.grid(row=1, column=2)
        self.pin_entry.grid(row=2, column=2)
        self.submit_pin.grid(row=2, column=3)        
        self.choose_pdf_btn.grid(row=4, column=2)
        self.encrypt_btn.grid(row=5, column=2)
        self.decrypt_btn.grid(row=6, column=2)
        self.label.grid(row=7, column=2)


        # USB port 
        self.detected_drives = set(
            self.get_usb_drives()
        )  
        self.monitor_thread = threading.Thread(target=self.monitor_usb, daemon=True)
        self.monitor_thread.start()

    def get_usb_drives(self):
        """Detect USB drives and return their mount points."""
        usb_drives = []
        for partition in psutil.disk_partitions():
            if "removable" in partition.opts:
                usb_drives.append(partition.mountpoint)
        return usb_drives

    def monitor_usb(self):
        """Continuously checks for new USB drives."""
        while True:
            time.sleep(2)  
            current_drives = set(self.get_usb_drives())

            new_drives = current_drives - self.detected_drives
            if new_drives:
                for drive in new_drives:
                    self.root.after(0, self.on_usb_inserted, drive)

            self.detected_drives = current_drives

    def find_pem_files(self, directory):
        pem_files = []
        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith(".pem"):
                    pem_files.append(os.path.join(root, file))
        return pem_files

    def on_usb_inserted(self, drive_path):
        os.system(
            f"xdg-open {drive_path}" if os.name == "posix" else f"start {drive_path}"
        )
        logging.debug('Pendrive detected')            
        self.pem_files = self.find_pem_files(drive_path)
        if not self.pem_files:
            logging.debug('No key detected on pendrive')            
            self.message.set('No key detected on pendrive!')  
            self.key_path = "./tt.pem"     
            return     
        self.key_path = self.pem_files[0]

        self.key_path_message.set(key_path)
        
    
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

        logging.debug(f'Key path: {self.key_path}')
        if self.key_path is None:
            logging.debug('No key detected!')            
            self.message.set('No key detected!')
            
        
        self.private_key = self.load_and_decrypt_private_key(self.key_path, pin)
        logging.debug(f'Private key: {self.private_key}')            
        self.pin_var.set("") 
        self.message.set('Key ready!')

                    
    def decrypt_private_key(self, encrypted_data, aes_key):
        iv = encrypted_data[:16]
        encrypted_private_key = encrypted_data[16:]

        cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)

        decrypted_padded = cipher_aes.decrypt(encrypted_private_key)

        padding_length = decrypted_padded[-1]
        private_key = decrypted_padded[:-padding_length]

        return private_key


    def derive_aes_key(self, pin):
        hasher = SHA256.new(pin.encode())
        return hasher.digest()
    
    def load_and_decrypt_private_key(self, file_path, pin):
        aes_key = self.derive_aes_key(pin)

        with open(file_path, "rb") as f:
            encrypted_data = f.read()

        decrypted_private_key = self.decrypt_private_key(encrypted_data, aes_key)

        private_key = RSA.import_key(decrypted_private_key)
        logging.debug("Private key decrypted successfully!")

        return private_key
    
    def encrypt_pdf(self):   
        if not self.private_key:
            self.message.set("Private key not loaded!")
            logging.debug("Private key not loaded!")
            return

        if not self.file_path:
            self.message.set("No PDF selected!")
            logging.debug("No PDF selected!")
            return
            
        with open(self.file_path, 'rb') as f:
            pdf_data = f.read()
            
        aes_key = get_random_bytes(32)
        iv = get_random_bytes(16)

        cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
        padding_len = 16 - len(pdf_data) % 16
        padded_pdf = pdf_data + bytes([padding_len]) * padding_len
        encrypted_pdf = cipher_aes.encrypt(padded_pdf)

        public_key = self.private_key.publickey()
        cipher_rsa = PKCS1_OAEP.new(public_key)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)        
            
        with open(self.file_path, "wb") as f:
            f.write(len(encrypted_aes_key).to_bytes(2, 'big'))
            f.write(encrypted_aes_key)
            f.write(iv)
            f.write(encrypted_pdf)
            logging.debug(f"PDF encrypted and saved to {self.file_path}")    
                
    def decrypt_pdf(self):
        if not self.private_key:
            self.message.set("Private key not loaded!")
            logging.debug("Private key not loaded!")
            return

        if not self.file_path:
            self.message.set("No PDF selected!")
            logging.debug("No PDF selected!")
            return

        with open(self.file_path, "rb") as f:
            # 1. Read key length
            key_len_bytes = f.read(2)
            if len(key_len_bytes) != 2:
                self.message.set("Invalid file format!")
                return
            key_len = int.from_bytes(key_len_bytes, 'big')

            # 2. Read encrypted AES key, IV, and encrypted PDF
            encrypted_aes_key = f.read(key_len)
            iv = f.read(16)
            encrypted_pdf = f.read()

            # 3. Decrypt AES key with RSA private key
            cipher_rsa = PKCS1_OAEP.new(self.private_key)
            try:
                aes_key = cipher_rsa.decrypt(encrypted_aes_key)
            except ValueError:
                self.message.set("Decryption failed. Invalid PIN or corrupted file.")
                logging.error("RSA decryption failed.")
                return

            # 4. Decrypt PDF with AES
            cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
            decrypted_padded = cipher_aes.decrypt(encrypted_pdf)
            padding_len = decrypted_padded[-1]
            if padding_len < 1 or padding_len > 16:
                self.message.set("Invalid padding. File may be corrupted.")
                return
            decrypted_pdf = decrypted_padded[:-padding_len]

            # 5. Save decrypted PDF (e.g., same name + "_decrypted.pdf")
            decrypted_path = self.file_path.replace(".pdf", "_decrypted.pdf").replace(".PDF", "_decrypted.pdf")
            with open(decrypted_path, "wb") as f:
                f.write(decrypted_pdf)

            logging.debug(f"PDF decrypted and saved to {decrypted_path}")
            self.message.set(f"Decrypted to:\n{os.path.basename(decrypted_path)}")
            
                        
    def choose_pdf(self):
        logging.debug("choose_pdf")
        file_path = tk.filedialog.askopenfilename(filetypes=[('Allowed Types', '*.pdf')], initialdir="./")
        if not file_path:
            logging.debug("No file selected.")
            self.message.set('No file selected.')

            return
        logging.debug(f"File selected: {file_path}")
        self.file_path = file_path



# Run the function
if __name__ == "__main__":
  print("App start")
  root = tk.Tk()
  app = encryption_app(root)
  root.mainloop()

