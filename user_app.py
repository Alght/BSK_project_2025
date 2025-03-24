from tkinter import Tk, filedialog, StringVar, Entry, Button
from Crypto.PublicKey import RSA

global pin 

global file_path

root = Tk()
root.title('RSA')

root.geometry("300x200")

pin_var = StringVar()


def submit():

    key_pair = RSA.generate(4096)

    pin=pin_var.get()
    public_key = key_pair.publickey().exportKey()
    private_key = key_pair.exportKey()

    print("The pin is : " + pin)
    print(public_key)
    print(private_key)

    with open ("./public.pem", "w") as pub_file:
        print("{}".format(public_key), file=pub_file)
    pin_var.set("")


def browse_file():
    initial_dir = './'
    file_path = filedialog.askopenfilename(initialdir=initial_dir, title="Select a file to save key")



# window elemensts
pin_entry=Entry(root, textvariable = pin_var, font = ('calibre',10,'normal'), show = '*')

browse_button = Button(root, text="Browse", command=browse_file)

sub_btn=Button(root, text = 'Submit', command = submit)


# placing window elemensts

pin_entry.grid(row=2,column=2)
sub_btn.grid(row=3,column=2)
browse_button.grid(row=5,column=2)

# window display
root.mainloop()