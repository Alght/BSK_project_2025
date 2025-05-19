import os
import psutil
import logging
import threading
import time
from Crypto.PublicKey import RSA
import functionality
from tkinter import Tk, filedialog, StringVar, Entry, Button, Label

logging.basicConfig(level=logging.DEBUG)

class encryption_app:

    def __init__(self, root):
        self.root = root
        self.message = StringVar()
        self.key_path_message = StringVar()
        logging.debug("App start")
        # variables for cryptography
        self.pin = ""
        self.pdf_file_path = ""
        self.private_key_path = None
        self.public_key_path = None
        self.private_key = None
        self.public_key = None
        self.cert = None
        self.pem_files = []

        # app GUI
        self.root.title("Cryptography app")
        self.root.minsize(200, 100)
        self.root.maxsize(400, 300)

        self.pin_var = StringVar()
        self.pin_entry = Entry(
            root, textvariable=self.pin_var, font=("calibre", 10, "normal"), show="*"
        )
        self.submit_pin = Button(root, text="Submit", command=self.submit_pin)
        self.choose_pdf_btn = Button(
            root, text="Choose PDF", command=self.choose_pdf
        )
        self.sign_pdf_btn = Button(root, text="Sign", command=self.sign_pdf)
        self.verify_btn = Button(root, text="Verify", command=self.verify_pdf)
        self.choose_pub_key_btn = Button(
            root, text="Choose public key", command=self.choose_pub_key
        )

        self.key_path_message.set("No key detected")
        self.label = Label(root, textvariable=self.message)
        self.key_label = Label(root, textvariable=self.key_path_message)
        self.key_label.grid(row=1, column=2)
        self.pin_entry.grid(row=2, column=2)
        self.submit_pin.grid(row=2, column=3)
        self.choose_pdf_btn.grid(row=4, column=2)
        self.sign_pdf_btn.grid(row=5, column=2)
        self.verify_btn.grid(row=6, column=2)
        self.choose_pub_key_btn.grid(row=7, column=2)
        self.label.grid(row=9, column=2)

        # USB port
        self.detected_drives = set(self.get_usb_drives())
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
        # find a pem file on inserted device
        logging.debug("Pendrive detected")
        self.pem_files = self.find_pem_files(drive_path)
        if not self.pem_files:
            logging.debug("No key detected on pendrive")
            self.message.set("No key detected on pendrive!")
            return
        self.private_key_path = self.pem_files[0]
        self.key_path_message.set(self.private_key_path)

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
            self.message.set("PIN cannot be empty!")
            return
        elif len(pin) < 4:
            logging.debug("PIN is too short!")
            self.message.set("PIN is too short!")
            return

        self.pin = pin

        if self.private_key_path is None:
            logging.debug("No key detected!")
            self.message.set("No key detected!")

        self.prepare_private_key()

        if self.private_key is None:
            return
        self.pin_var.set("")
        self.message.set("Key ready!")

    def prepare_private_key(self):
        self.private_key = self.load_and_decrypt_private_key(
            self.private_key_path, self.pin
        )
        logging.debug(f"Private key: {self.private_key}")

    def choose_pdf(self):
        logging.debug("choose_pdf")
        file_path = filedialog.askopenfilename(
            filetypes=[("Allowed Types", "*.pdf")], initialdir="./"
        )
        if not file_path:
            logging.debug("No file selected.")
            self.message.set("No file selected.")

            return
        logging.debug(f"File selected: {file_path}")
        self.pdf_file_path = file_path

    def choose_pub_key(self):
        logging.debug("choose_pub_key")
        file_path = filedialog.askopenfilename(
            filetypes=[("Allowed Types", "*.pem")], initialdir="./"
        )
        if not file_path:
            logging.debug("No file selected.")
            self.message.set("No file selected.")
            return
        logging.debug(f"File selected: {file_path}")
        self.prepare_public_key(file_path)
        self.public_key_path = file_path

    def prepare_public_key(self, file_path):
        logging.debug(f"prepare_public_key")
        with open(file_path, "rb") as f:
            self.public_key = f.read()
            logging.debug(f"Public key: {self.public_key}")
            self.public_key = RSA.import_key(self.public_key)
            logging.debug(f"Public key: {self.public_key}")
            self.message.set(f"Public key: {file_path}")


    def load_and_decrypt_private_key(self, file_path, pin):
        logging.debug("load_and_decrypt_private_key")
        
        if file_path is None:
            logging.debug("No key path")
            return
        with open(file_path, "rb") as f:
            encrypted_data = f.read()

        aes_key = functionality.derive_aes_key(pin)
        private_key = functionality.decrypt_private_key(encrypted_data, aes_key)

        logging.debug("Private key decrypted successfully!")
        logging.debug(private_key)

        return private_key

    # sign and verify

    def sign_pdf(self, change_name=True):

        with open(self.pdf_file_path, "rb") as inf:
            i = inf.read()
    

        
        signed_data = functionality.sign_pdf_full(self.pdf_file_path, self.private_key)
        # with open(
        #     (
        #         self.pdf_file_path.replace(".pdf", "_signed.pdf")
        #         if change_name
        #         else self.pdf_file_path
        #     ),
        #     "wb",
        # ) as outf:
        #     outf.write(signed_data)

    def verify_pdf(self):
        logging.debug("verify_pdf")
        if self.public_key is None:
            logging.debug("No public key detected!")
            self.message.set("No public key detected!")
            return
        if not self.pdf_file_path or len(self.pdf_file_path) == 0:
            logging.debug("No PDF!")
            return
        verified = functionality.verify_pdf(self.pdf_file_path, self.public_key)
        if verified:
            logging.debug("Verified")
            self.message.set("Verified!")
        else:
            logging.debug("Not verified")
            self.message.set("Not verified!")




# Run the function
if __name__ == "__main__":
    logging.debug("Start")

    root = Tk()
    app = encryption_app(root)
    root.mainloop()

