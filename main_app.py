import os
import psutil
import tkinter as tk
from Crypto.PublicKey import RSA

import threading
import time
from tkinter import messagebox


class encryption_app:

    def __init__(self, root):
        
        self.pin_var = tk.StringVar()
        self.file_path = "./"
        self.root = root
        self.root = root
        self.root.title("USB Detector")
        self.label = tk.Label(
            root, text="Waiting for USB device...", font=("Arial", 12)
        )
        self.label.pack(pady=20)

        self.pem_files = []

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
        self.label.config(text=f"USB inserted: {drive_path}")
        os.system(
            f"xdg-open {drive_path}" if os.name == "posix" else f"start {drive_path}"
        )
        self.pem_files = self.find_pem_files(drive_path)

    def browse_file():
        initial_dir = "./"
        file_path = tk.filedialog.askopenfilename(
            initialdir=initial_dir, title="Select a file to encrypt"
        )

    def chose_file_to_encrypt():
        pass
    
    def submit(self):
        pin = self.pin_var.get().strip()
        if not pin:
            print("PIN cannot be empty!")
            return
        elif pin.len() < 4:
            print("PIN is too short!")
            return

        self.pin_var.set("")  # Clear PIN field

# Run the function
if __name__ == "__main__":
    root = tk.Tk()
    app = encryption_app(root)
    root.mainloop()
