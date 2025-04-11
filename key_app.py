from tkinter import Tk, filedialog, StringVar, Entry, Button, simpledialog
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
import os
import logging

logging.basicConfig(level=logging.DEBUG)
class KeyApp:
    def __init__(self, root):
        self.pin_var = StringVar()
        self.file_path = "./"
        self.root = root

        # GUI Elements
        pin_entry = Entry(
            root, textvariable=self.pin_var, font=("calibre", 10, "normal"), show="*"
        )
        browse_button = Button(root, text="Browse", command=self.choose_location)
        sub_btn = Button(root, text="Submit", command=self.submit)

        pin_entry.grid(row=2, column=2)
        browse_button.grid(row=3, column=2)
        sub_btn.grid(row=5, column=3)

    def generate_rsa_key(self):
        return RSA.generate(4096)

    def derive_aes_key(self, pin):
        hasher = SHA256.new(pin.encode())
        return hasher.digest()

    def submit(self):
        pin = self.pin_var.get().strip()
        if not pin:
            logging.debug("PIN cannot be empty!")
            return
        elif len(pin) < 4:
            logging.debug("PIN is too short!")
            return
        key_pair = self.generate_rsa_key()
        aes_key = self.derive_aes_key(pin)

        self.encrypt_private_key(key_pair.export_key(), aes_key, self.file_path)
        logging.debug(f'Private key: {key_pair.export_key()}')
        logging.debug(f'Public key: {key_pair.publickey().export_key()}')


        pub_key_path = self.file_path.replace(".pem", "_pub.pem")
        self.save_public_key(key_pair.publickey(), pub_key_path)

        self.pin_var.set("")

    def encrypt_private_key(self, private_key, aes_key, output_file):
        iv = os.urandom(16)
        cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)

        padding_length = 16 - (len(private_key) % 16)
        private_key_padded = private_key + bytes([padding_length]) * padding_length

        encrypted_data = cipher_aes.encrypt(private_key_padded)

        with open(output_file, "wb") as f:
            f.write(iv + encrypted_data)

        logging.debug(f"Encrypted private key saved to {output_file}")

    def save_public_key(self, public_key, output_file):
        with open(output_file, "wb") as f:
            f.write(public_key.export_key(format="PEM"))
        logging.debug(f"Public key saved to {output_file}")

    def choose_location(self):
        save_path = filedialog.asksaveasfilename(defaultextension=".pem", filetypes=[("Privacy-Enhanced Mail", "*.pem")])
        if not save_path:
            logging.debug("No file selected.")
            return
        logging.debug(f"File selected: {save_path}")
        self.file_path = save_path
        
if __name__ == "__main__":
    root = Tk()
    root.title("RSA Key Generator")
    root.geometry("300x200")

    KeyApp(root)
    root.mainloop()
