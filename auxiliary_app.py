from tkinter import Tk, filedialog, StringVar, Entry, Button, Label
import logging
import functionality

logging.basicConfig(level=logging.DEBUG)


class AuxiliaryApp:
    def __init__(self, root):
        """
        Initialize the RSA Key Generator app.

        This class sets up a simple Tkinter GUI to collect a 4-digit PIN and a file path to save a generated RSA private key.
        
        Parameters:
            root (Tk): The root Tkinter window.

        Attributes:
            pin (str): 4-digit PIN entered by the user.
            file_path (str or None): Path to save the generated private key.
            root (Tk): The root Tkinter window.
            message(StringVar): Stores the status or instruction message.
            label(Label): Displays messages to the user.
            pin_var (StringVar): Tkinter variable linked to the PIN entry widget.
        """
        self.pin = ""
        self.file_path = None

        self.root = root
        self.root.title("RSA Key Generator")
        self.root.geometry("200x100")
        self.message = StringVar()
        self.label = Label(root, textvariable=self.message)
        self.pin_var = StringVar()
        pin_entry = Entry(
            root, textvariable=self.pin_var, font=("calibre", 10, "normal"), show="*"
        )
        browse_button = Button(
            root, text="Choose location", command=self.choose_location
        )
        sub_btn = Button(root, text="Submit", command=self.submit)

        pin_entry.grid(row=2, column=2)
        browse_button.grid(row=3, column=2)
        sub_btn.grid(row=5, column=2)
        self.label.grid(row=6, column=2)

    def submit(self):
        """
        Handle the submission of the PIN and key file location.

        Validates that:
            - The PIN is not empty.
            - The PIN is at least 4 characters long.
            - A file path has been selected.

        If all checks pass, it calls `create_keys()` to generate RSA keys.
        Otherwise, displays appropriate messages to the user.

        Side Effects:
            - Updates `self.pin`, `self.message`, and `self.file_path`.
            - Clears the PIN entry field after key creation.
        """
        self.pin = self.pin_var.get().strip()
        if not self.pin:
            logging.debug("PIN cannot be empty")
            self.message.set("PIN cannot be empty!")
            return
        elif len(self.pin) < 4:
            logging.debug("PIN is too short")
            self.message.set("PIN is too short!")
            return
        if not self.file_path:
            logging.debug("No file selected.")
            self.message.set("No file selected.")
            return
        

        self.create_keys()
        self.pin_var.set("")
        self.file_path = None

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
        self.message.set("Creating keys...")

        functionality.create_keys(self.pin, self.file_path)


        logging.debug("Keys created")
        self.message.set("Keys created")    

    def choose_location(self):
        """
        Open a file dialog to choose a location to save the private key.

        A file save dialog is shown for the user to select a `.pem` file location.

        Side Effects:
            - Updates `self.file_path` with the selected or provided path.
            - Logs debug messages about file selection.
        """
        save_path = filedialog.asksaveasfilename(
            defaultextension=".pem", filetypes=[("Privacy-Enhanced Mail", "*.pem")]
        )
        if not save_path:
            logging.debug("No file selected.")
            return
        logging.debug(f"File selected: {save_path}")
        self.file_path = save_path


if __name__ == "__main__":
    root = Tk()
    k = AuxiliaryApp(root)
    root.mainloop()
