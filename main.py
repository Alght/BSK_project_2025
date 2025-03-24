import os
import psutil
from tkinter import Tk, filedialog

def get_usb_mountpoints():
    """Detect USB drives and return their mount points."""
    usb_drives = []
    for partition in psutil.disk_partitions():
        if 'removable' in partition.opts:
            usb_drives.append(partition.mountpoint)  # Get the mount point
    return usb_drives

def pick_file_from_usb():
    """Allow user to pick a file from a detected USB drive."""
    usb_mounts = get_usb_mountpoints()
    
    if not usb_mounts:
        print("No USB drive detected.")
        return None

    # Open file dialog in the first detected USB drive
    root = Tk()
    root.withdraw()  # Hide the main Tkinter window

    initial_dir = usb_mounts[0]  # Use the first USB drive
    file_path = filedialog.askopenfilename(initialdir=initial_dir, title="Select a file from USB")

    if file_path:
        print(f"Selected file: {file_path}")
        return file_path
    else:
        print("No file selected.")
        return None

# Run the function
pick_file_from_usb()
