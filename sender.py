import tkinter as tk
import tkinter.messagebox
import ttkbootstrap as ttk
from ttkbootstrap.scrolled import ScrolledText
from dtn_aes import encrypt, decrypt
import socket
from tkinter import filedialog
import os


def get_wifi_ip() -> str:
    # Get the hostname
    hostname = socket.gethostname()

    # Get all IP addresses associated with the hostname
    ip_addresses = socket.getaddrinfo(hostname, None, socket.AF_INET)

    # Filter and retrieve the IP address of the Wi-Fi adapter
    wifi_ip = [ip[4][0] for ip in ip_addresses if ip[4][0].startswith("192.168.1.")]

    # Return the Wi-Fi IP address if available
    if wifi_ip:
        return wifi_ip[0]
    else:
        return ""


def encrypt_decrypt():
    key_length = int(key_length_var.get())
    password = pwd_var.get()
    plaintext = plaintext_text.get('1.0', tk.END)

    ciphertext = encrypt(plaintext.encode(), password, key_length)
    encrypted_var.set(ciphertext)

    decrypted_var.set(decrypt(ciphertext, password, key_length).decode())


# window
window = ttk.Window(themename='journal')
window.title('tab')

# notebook
notebook = ttk.Notebook(window)
notebook.pack()

# aes tab
aes_tab = ttk.Frame(notebook)
notebook.add(aes_tab, text='AES')

top_bar = ttk.Frame(aes_tab)
top_bar.pack()

key_length_label = ttk.Label(top_bar, text='key length in bytes')
key_length_label.pack(side='left')

items = ("16", "24", "32")
key_length_var = tk.StringVar(value=items[0])
key_length_combo = ttk.Combobox(top_bar, textvariable=key_length_var)
key_length_combo.pack(side='left')
key_length_combo['values'] = items

gap_separator = ttk.Separator(top_bar, orient='vertical')
gap_separator.pack(side='left', padx=30)

pwd_label = ttk.Label(top_bar, text='enter password here')
pwd_label.pack(side='left')

pwd_var = tk.StringVar(value='secretPassword')
pwd_entry = ttk.Entry(top_bar, textvariable=pwd_var)
pwd_entry.pack(side='left', padx=30)

en_decrypt_btn = ttk.Button(top_bar, text='encrypt and decrypt', command=lambda: encrypt_decrypt())
en_decrypt_btn.pack(side='left')

# Text to be encrypted
plaintext_label = ttk.Label(aes_tab, text='Text to Encrypt:')
plaintext_label.pack()

plaintext_text = ScrolledText(aes_tab, padding=5, height=10, autohide=True, wrap=tk.WORD)
plaintext_text.pack(fill=tk.BOTH, expand=tk.YES)

# Encrypted text
encrypted_label = ttk.Label(aes_tab, text='Encrypted Text:')
encrypted_label.pack()

encrypted_var = tk.StringVar()
encrypted_text = ttk.Label(aes_tab, padding=5, textvariable=encrypted_var)
encrypted_text.pack(fill=tk.BOTH, expand=tk.YES)

# Decrypted text
decrypted_label = ttk.Label(aes_tab, text='Decrypted Text:')
decrypted_label.pack()

decrypted_var = tk.StringVar()
decrypted_text = ttk.Label(aes_tab, padding=5, textvariable=decrypted_var)
decrypted_text.pack(fill=tk.BOTH, expand=tk.YES)

# socket tab
socket_tab = ttk.Frame(notebook)
notebook.add(socket_tab, text='SOCKET')

# client frame

client_frame = ttk.Frame(socket_tab)
client_frame.pack()

addr_to_connect_to_var = tk.StringVar(value=get_wifi_ip())
addr_to_connect_to_label = tk.Label(client_frame, text='address to connect to')
addr_to_connect_to_label.pack()
addr_to_connect_to_entry = tk.Entry(client_frame, textvariable=addr_to_connect_to_var)
addr_to_connect_to_entry.pack()

port_to_connect_to_var = tk.StringVar(value='5050')
port_to_connect_to_label = tk.Label(client_frame, text='port to connect to')
port_to_connect_to_label.pack()
port_to_connect_to_entry = tk.Entry(client_frame, textvariable=port_to_connect_to_var)
port_to_connect_to_entry.pack()

# client_socket_key_len_label = ttk.Label(client_frame, text='key length in bytes 16,24,32')
# client_socket_key_len_label.pack()
# client_socket_key_len_var = tk.StringVar(value='16')
# client_socket_key_len_entry = ttk.Entry(client_frame, textvariable=client_socket_key_len_var)
# client_socket_key_len_entry.pack()

client_socket_key_len_label = ttk.Label(client_frame, text='key length in bytes 16, 24, 32')
client_socket_key_len_label.pack()

client_socket_key_len_var = tk.StringVar(value='16')
client_socket_key_len_combo = ttk.Combobox(client_frame, textvariable=client_socket_key_len_var)
client_socket_key_len_combo.pack()
client_socket_key_len_combo["values"] = ("16", "24", "32")

client_socket_password_label = ttk.Label(client_frame, text='password')
client_socket_password_label.pack()
client_socket_password_var = tk.StringVar(value='defaultPassword')
client_socket_password_entry = ttk.Entry(client_frame, textvariable=client_socket_password_var)
client_socket_password_entry.pack()


def add_file():
    file_path = filedialog.askopenfilename()
    file_path_label_var.set(file_path)


add_file_btn = ttk.Button(client_frame, text='add file', command=lambda: add_file())
add_file_btn.pack(pady=20)


def decrypt_send():
    if file_path_label_var.get() == 'no file chosen':
        tkinter.messagebox.showinfo("warning", "choose a file")
    file_path = file_path_label_var.get()
    file_name = os.path.basename(file_path)
    host = addr_to_connect_to_var.get()
    port = int(port_to_connect_to_var.get())

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((host, port))

    file = open(file_path, 'rb')

    client.sendall(file_name.encode())
    print(file_name)
    data = file.read()

    encrypted = encrypt(plaintext=data,
                        password=client_socket_password_var.get(),
                        key_length=int(client_socket_key_len_var.get()))
    client.sendall(encrypted)
    client.sendall(b"<END>")

    client.close()
    file.close()
    tkinter.messagebox.showinfo('sucess','file sent sucessfully')


decrypt_send_btn = ttk.Button(client_frame, text='decrypt and send', command=lambda: decrypt_send())
decrypt_send_btn.pack()

file_path_label_var = tk.StringVar(value='no file chosen')
file_path_label = ttk.Label(client_frame, textvariable=file_path_label_var)
file_path_label.pack()

# run
window.mainloop()
