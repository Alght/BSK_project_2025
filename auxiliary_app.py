from tkinter import Tk, filedialog, StringVar, Entry, Button, Label
import logging
import functionality
import os
logging.basicConfig(level=logging.INFO)


class AuxiliaryApp:
    def __init__(self, root):
        """
        Initialize the RSA Key Generator app.
        This class sets up a simple Tkinter GUI to collect a 4-digit PIN and a file path to save a generated RSA private key.
        
        Parameters:
            root (Tk): The root Tkinter window.

        Attributes:
            root (Tk): The root Tkinter window.    
            message_key(StringVar): Stores the status or instruction message for key / key path.
            label_key(Label): Displays messages to the user.
            message_pin(StringVar): Stores the status or instruction message for pin.
            label_pin(Label): Displays messages to the user.

            pin_var (StringVar): Tkinter variable linked to the PIN entry widget.
            pin (str): 4-digit PIN entered by the user.
            file_path (str or None): Path to save the generated private key.               
        """
        self.pin = ""
        self.file_path = None

        self.root = root
        self.root.title("RSA Key Generator")
        self.root.geometry("250x200")
        self.message_key = StringVar()
        self.label_key = Label(root, textvariable=self.message_key)
        self.message_pin = StringVar()
        self.label_pin = Label(root, textvariable=self.message_pin)
        self.pin_var = StringVar()


        pin_entry = Entry(root, textvariable=self.pin_var, font=("calibre", 10, "normal"), show="*")
        browse_button = Button(root, text="Choose location", command=self.choose_location)
        sub_btn = Button(root, text="Submit", command=self.submit)

        # GUI setup
        
        pin_entry.grid(row=2, column=2)
        browse_button.grid(row=3, column=2)
        sub_btn.grid(row=5, column=2)
        self.label_key.grid(row=6, column=2)       
        self.label_pin.grid(row=7, column=2)


    def submit(self):
        """
        Handle the submission of the PIN and key file location.

        Validates that:
            - The PIN is not empty.
            - The PIN has 4 characters.
            - A file path has been selected.

        If all checks pass, it calls `create_keys()` to generate RSA keys.
        Otherwise, displays appropriate messages to the user.

        Side Effects:
            - Updates `self.pin`, `self.message`, and `self.file_path`.
            - Clears the PIN entry field after key creation.
        """
        self.message_pin.set("")

        self.pin = self.pin_var.get().strip()
        create = True
        if not self.pin:
            logging.debug("PIN cannot be empty")
            self.message_pin.set("PIN cannot be empty")
            create = False
        elif len(self.pin) < 4:
            logging.debug("PIN is too short")
            self.message_pin.set("PIN is too short")
            create = False
        elif len(self.pin) > 4:
            logging.debug("PIN is too long")
            self.message_pin.set("PIN is too short")
            create = False
        if not self.file_path:
            logging.debug("No file selected")
            self.message_key.set("No file selected")
            create = False


        if create:
            self.create_keys()
            self.pin_var.set("")
            self.file_path = None
            self.message_pin.set("")


    def create_keys(self):
        """
        Create RSA keys using the provided PIN and file path.

        This method delegates key generation to the `functionality.create_keys()` 
        function, passing the  PIN and selected file path and
        updates the GUI message before and after key creation.

        Side Effects:
            - Calls `functionality.create_keys(self.pin, self.file_path)` to generate keys.
            - Updates the status message shown in the GUI via `self.message`.
            - Logs debug messages about key creation.

        """
        logging.debug("Creating keys...")
        self.message_key.set("Creating keys...")
        functionality.create_keys(self.pin, self.file_path)
        logging.debug("Keys created")
        self.message_key.set("Keys created")    

    def choose_location(self):
        """
        A file save dialog is shown for the user to select a `.pem` file location.

        Side Effects:
            - Updates `self.file_path` with the selected or provided path.
            - Logs debug messages about file selection.
        """
        save_path = filedialog.asksaveasfilename(
            defaultextension=".pem", filetypes=[("Privacy-Enhanced Mail", "*.pem")]
        )
        if not save_path:
            logging.debug("No location selected.")
            return
        logging.debug(f"Public key: {os.path.basename(save_path)}")
        self.message_key.set(f"Private key path: {os.path.basename(save_path)}\n Public key will have *_pub.pem name")    
        self.file_path = save_path


if __name__ == "__main__":
    logging.debug("Start")

    root = Tk()
    k = AuxiliaryApp(root)
    root.mainloop()
