import os
import psutil
import logging
import threading
import time
from Crypto.PublicKey import RSA
import functionality
from tkinter import Tk, filedialog, StringVar, Entry, Button, Label

logging.basicConfig(level=logging.INFO)
logging.getLogger("pyhanko.sign.validation.generic_cms").setLevel(logging.ERROR)
logging.getLogger("pyhanko_certvalidator").setLevel(logging.ERROR)
class EncryptionApp:

    def __init__(self, root):
        """
        GUI application for PDF signing and signature verification using RSA and AES encryption.

        This application provides a graphical interface for:
        - Entering a PIN to decrypt an RSA private key.
        - Selecting a PDF file to sign or verify.
        - Choosing a public key file for signature verification.
        - Automatically detecting USB drives to retrieve keys.

        Args:
            root (Tk): The root Tkinter window.

        Attributes:
            root (Tk): Main Tkinter window.
            pin (str): PIN used to derive AES key.
            pdf_file_path (str): Path to the selected PDF file.
            private_key_path (str or None): Path to the detected encrypted private key file.
            public_key_path (str or None): Path to the selected public key file.
            private_key (RSAPrivateKey or None): Decrypted private RSA key.
            public_key (RSAPublicKey or None): Loaded public RSA key.
            cert (x509.Certificate or None): Certificate generated for signing.
            pin_var (StringVar): Linked to the PIN entry widget.
            pin_entry (Entry): PIN input widget.
            submit_pin (Button): Button to submit the PIN.
            choose_pdf_btn (Button): Button to select a PDF for signing/verifying.
            sign_pdf_btn (Button): Button to sign the selected PDF.
            verify_btn (Button): Button to verify the PDF signature.
            choose_pub_key_btn (Button): Button to select a public key file.

            message_pdf (StringVar): Status or instruction message_pdf displayed to the user.
            message_private_key (StringVar): Message displaying key detection info.
            message_public_key (StringVar): Message displaying chosen public key info.
            message_general (StringVar): Message displaying general info.

            label_pdf (Label): Displays general messages to the user.
            label_private_key (Label): Displays key detection status.
            label_public_key (Label): Displays key detection status.
            label_general (Label): Displays general messages to the user.

            detected_drives (set): Set of USB drives detected on launch.
            monitor_thread (Thread): Background thread to monitor USB drive changes.
        """
        self.root = root
        self.message_pdf = StringVar()
        self.message_private_key = StringVar()
        self.message_public_key = StringVar()
        self.message_general = StringVar()

        logging.debug("App start")
        self.pin = ""
        self.pdf_file_path = ""
        self.private_key_path = None
        self.public_key_path = None
        self.private_key = None
        self.public_key = None
        self.cert = None

        # app GUI
        self.root.title("Cryptography app")
        self.root.minsize(200, 100)
        self.root.maxsize(400, 300)

        self.pin_var = StringVar()
        self.pin_entry = Entry(root, textvariable=self.pin_var, font=("calibre", 10, "normal"), show="*")
        self.submit_pin = Button(root, text="Submit", command=self.submit_pin)
        self.choose_pdf_btn = Button(root, text="Choose PDF", command=self.choose_pdf)
        self.sign_pdf_btn = Button(root, text="Sign", command=self.sign_pdf)
        self.verify_btn = Button(root, text="Verify", command=self.verify_pdf)
        self.choose_pub_key_btn = Button(root, text="Choose public key", command=self.choose_pub_key)

        self.message_private_key.set("No private key detected")
        self.message_public_key.set("No public key chosen")

        self.label_pdf = Label(root, textvariable=self.message_pdf)
        self.label_private_key = Label(root, textvariable=self.message_private_key)
        self.label_public_key = Label(root, textvariable=self.message_public_key)
        self.label_general = Label(root, textvariable=self.message_general)

        # GUI setup
        self.pin_entry.grid(row=2, column=1)
        self.submit_pin.grid(row=2, column=2)
        self.choose_pdf_btn.grid(row=1, column=1)
        self.sign_pdf_btn.grid(row=3, column=2)
        self.verify_btn.grid(row=5, column=2)
        self.choose_pub_key_btn.grid(row=5, column=1)
        self.label_general.grid(row=8, column=1)

        self.label_pdf.grid(row=9, column=1)
        self.label_private_key.grid(row=10, column=1)
        self.label_public_key.grid(row=11, column=1)

        # USB port
        self.detected_drives = set(self.get_usb_drives())
        self.monitor_thread = threading.Thread(target=self.monitor_usb, daemon=True)
        self.monitor_thread.start()

    def get_usb_drives(self):
        """
        Detect currently mounted USB drives.

        Uses `psutil.disk_partitions()` to scan for removable drives by checking
        the 'opts' field of each partition.

        Returns:
            list: A list of mount points for all detected USB drives.
        """
        usb_drives = []
        for partition in psutil.disk_partitions():
            if "removable" in partition.opts:
                usb_drives.append(partition.mountpoint)
        return usb_drives

    def monitor_usb(self):
        """
        Continuously monitor USB drives for new insertions.

        This method runs in a background thread and checks
        the currently mounted USB drives by calling `get_usb_drives()` every 2 seconds.

        When a new USB drive is detected, it schedules a call to `on_usb_inserted` on the main
        Tkinter thread using `root.after` to safely handle UI updates.

        Runs indefinitely as a daemon thread.

        Returns:
            None           
        """
        while True:
            time.sleep(2)
            current_drives = set(self.get_usb_drives())

            new_drives = current_drives - self.detected_drives
            if new_drives:
                for drive in new_drives:
                    self.root.after(0, self.on_usb_inserted, drive)

            self.detected_drives = current_drives

    def on_usb_inserted(self, drive_path):
        """
        Continuously monitor USB drives for new insertions.

        Args:
            drive_path (str): path to detectedd USB.

        This method calls 'find_pem_files()' to check if there are any .pem files on inserted USB drive and logs the operatin.
        If there is a .pem file its path is saved to self.private_key_path.

        Returns:
            None           
        """
        logging.debug("Pendrive detected")
        pem_files = self.find_pem_files(drive_path)

        if self.private_key_path:
            return
        if not pem_files:
            logging.debug("No key detected on pendrive")
            return
        
        self.private_key_path = pem_files[0]
        self.message_private_key.set(f"Private key selected: {os.path.basename(self.private_key_path)}, submit PIN")

    def find_pem_files(self, directory):
        """
        Checks all files in given directory and returns ones with .pem extension.

        Args:
            directory (str): path to directory with private key.
        
        Returns:
            list: A list of files with .pem extension.

        Returns:
            None   
        """
        pem_files = []
        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith(".pem"):
                    pem_files.append(os.path.join(root, file))
        return pem_files

    def submit_pin(self):
        """
        Handle the submission of the PIN, private key must be detected for the function to work.

        Loads private key from detected file with  `prepare_private_key()` function.

        Side Effects:
        - Private key is loaded into memory.
        - Logs pin length and key.
        - Appropriate message_pdf is shown.
        - PIN input is cleared.

        Returns:
            None               
        """        
        pin = self.pin_var.get().strip()
        if not pin:
            logging.debug("PIN cannot be empty!")
            self.message_general.set("PIN cannot be empty!")
            return
        elif len(pin) < 4:
            logging.debug("PIN is too short!")
            self.message_general.set("PIN is too short!")
            return

        self.pin = pin

        if self.private_key_path is None:
            logging.debug("No key detected!")
            self.message_general.set("No key detected!")

        self.prepare_private_key()

        if self.private_key is None:
            self.message_private_key.set("Wrong key or PIN")
            return
        self.pin_var.set("")
        self.message_private_key.set("Private key ready!")

    def prepare_private_key(self):
        """
        Load and decrypt private key using pin. 

        Side Effects:
        - Private key is decrypted and loaded into memory.
        - Logs encryption status.

        Returns:
            None               
        """         
        logging.debug("load_and_decrypt_private_key")
        
        if self.private_key_path is None:
            logging.debug("No key path")
            return
        with open(self.private_key_path, "rb") as f:
            encrypted_data = f.read()

        aes_key = functionality.derive_aes_key(self.pin)
        self.private_key = functionality.decrypt_private_key(encrypted_data, aes_key)
        if self.private_key:
            logging.debug("Private key decrypted successfully!")
        else:
            logging.debug("Wrong private key or PIN!")


    def choose_pdf(self):
        """
        Open a file dialog to choose PDF.

        Side Effects:
        - PDF file path is saved.
        - Logs debug information.

        Returns:
            None               
        """                  
        logging.debug("choose_pdf")
        file_path = filedialog.askopenfilename(
            filetypes=[("Allowed Types", "*.pdf")], initialdir="./"
        )
        if not file_path:
            logging.debug("No file selected.")
            self.message_pdf.set("No file selected.")

            return
        logging.debug(f"File selected: {file_path}")
        self.message_pdf.set(f"PDF selected: {os.path.basename(file_path)}")
        self.pdf_file_path = file_path

    def choose_pub_key(self):
        """
        Open a file dialog to choose public key.

        Side Effects:
        - Public key is loaded into memory.
        - Logs debug messages about the operation.

        Returns:
            None               
        """           
        logging.debug("choose_pub_key")
        file_path = filedialog.askopenfilename(
            filetypes=[("Allowed Types", "*.pem")], initialdir="./"
        )
        if not file_path:
            logging.debug("No file selected.")
            self.message_public_key.set("No public key file selected.")
            return
        logging.debug(f"File selected: {file_path}")
        self.prepare_public_key(file_path)
        self.public_key_path = file_path

    def prepare_public_key(self, file_path):
        """
        Open a file dialog to choose public key. Key format is checked and if it is supported key is loaded into memory, otherwise it is set to None.

        Args:
            file_path (str): Path to public key.

        Side Effects:
        - Public key is loaded into memory.
        - Logs debug messages about the operation.

        Returns:
            None       
        """           
        logging.debug(f"prepare_public_key")
        try:
            with open(file_path, "rb") as f:
                key_data = f.read()
                self.public_key = RSA.import_key(key_data)
                logging.debug(f"Public key imported successfully: {self.public_key}")
                self.message_public_key.set(f"Public key: {file_path.split('/')[-1]}")
        except (ValueError, IndexError, TypeError) as e:
            logging.error(f"Failed to import public key: {e}")
            self.public_key = None
            self.message_public_key.set("Wrong public key format")

    def sign_pdf(self):
        """
        Sign pdf with `sign_pdf_full()` function.

        Side Effects:
        - PDF is signed.
        - Logs debug messages about the operation.
        - Shows approriate messages.

        Returns:
            None               
        """   
        msg = ""

        if not self.pdf_file_path:
            msg += "No PDF chosen\n"
        if not self.private_key:
            msg += "No private key loaded!\n"

        if msg:
            self.message_general.set(msg)
            return
        
        else:
            if functionality.sign_pdf_full(self.pdf_file_path, self.private_key ):        
                self.message_general.set(f"PDF was succesfully signed")
                logging.debug(f"PDF was succesfully signed")
            else:
                self.message_general.set(f"Error during signing process")
                logging.error(f"Error during signing process")


    def verify_pdf(self):
        """
        Verify pdf with `verify_pdf()` function.

        Side Effects:
        - PDF is verified.
        - Logs debug messages about the operation.
        - Shows approriate messages.

        Returns:
            None           
        """     

        msg = ""
        logging.debug("verify_pdf")
        if self.public_key is None:
            logging.debug("No public key loaded")
            msg += "No public key\n"
        if not self.pdf_file_path or len(self.pdf_file_path) == 0:
            logging.debug("No PDF path")
            msg += "No PDF chosen\n"
        
        if msg:
            self.message_general.set(msg)
            return     
        verified = functionality.verify_pdf(self.pdf_file_path, self.public_key)
        if verified:
            logging.debug("Verified")
            self.message_general.set("Verified!")
        else:
            logging.debug("Not verified")
            self.message_general.set("Not verified!")



if __name__ == "__main__":
    logging.debug("Start")

    root = Tk()
    app = EncryptionApp(root)
    root.mainloop()

