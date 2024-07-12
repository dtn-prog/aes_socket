import tkinter as tk
import ttkbootstrap as ttk
from ttkbootstrap.scrolled import ScrolledText
import tkinter as tk
import ttkbootstrap as ttk
from ttkbootstrap.scrolled import ScrolledText
from dtn_aes import encrypt, decrypt
import socket
from tkinter import filedialog
import os
import threading


def server_on_off():



    server_addr_var.set(f'listening on [{addr_to_bind_to_var.get()}, {port_to_bind_to_var.get()}]')
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((addr_to_bind_to_var.get(), int(port_to_bind_to_var.get())))

    def server_thread():
        server.listen()

        client, addr = server.accept()
        client_addr_var.set(f'{addr} connected')
        loading_label_var.set('loading...')

        file_name = client.recv(1024).decode()
        file_bytes = b''

        done = False

        while not done:
            data = client.recv(1024)
            print('received>>>....')
            if file_bytes[-5:] == b'<END>':
                done = True
            else:
                file_bytes += data

        file_extension = os.path.splitext(file_name)[1]
        print(file_extension)
        print(type(file_extension))

        file = filedialog.asksaveasfile(mode='wb', defaultextension=file_extension, initialfile=file_name)
        file.write(file_bytes[:-5])

        client.close()
        file.close()
        server.close()
        server_addr_var.set(f'waiting on [{get_wifi_ip()}, 5050]')
        client_addr_var.set(f'no one connected')
        loading_label_var.set('nothing loading')

    server_thread = threading.Thread(target=server_thread)
    server_thread.start()



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
window.title('AES Encryption')

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

pwd_var = tk.StringVar(value='defaultPassword')
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

# server_frame
server_frame = ttk.Frame(socket_tab)
server_frame.pack()

addr_to_bind_to_label = ttk.Label(server_frame, text='address to bind to')
addr_to_bind_to_label.pack()
addr_to_bind_to_var = tk.StringVar(value=get_wifi_ip())
addr_to_bind_to_entry = ttk.Entry(server_frame, textvariable=addr_to_bind_to_var)
addr_to_bind_to_entry.pack()

port_to_bind_to_label = ttk.Label(server_frame, text='port to bind to')
port_to_bind_to_label.pack()
port_to_bind_to_var = tk.StringVar(value='5050')
port_to_bind_to_entry = ttk.Entry(server_frame, textvariable=port_to_bind_to_var)
port_to_bind_to_entry.pack()

server_addr_var = tk.StringVar(value=f'waiting on ({addr_to_bind_to_var.get()}, {port_to_bind_to_var.get()})')
server_addr_label = ttk.Label(server_frame, textvariable=server_addr_var)
server_addr_label.pack()

client_addr_var = tk.StringVar(value='no client connected')
client_addr_label = ttk.Label(server_frame, textvariable=client_addr_var)
client_addr_label.pack()

loading_label_var = tk.StringVar(value='nothing loading')
loading_label = ttk.Label(server_frame, textvariable=loading_label_var)
loading_label.pack()

server_btn = ttk.Button(server_frame, text='on/of server', command=lambda: server_on_off())
server_btn.pack()

# server_socket_key_len_label = ttk.Label(server_frame, text='key lengths in bytes 16,24,32')
# server_socket_key_len_label.pack()
# server_socket_key_len_var = tk.StringVar(value='16')
# server_socket_key_len_entry = ttk.Entry(server_frame, textvariable=server_socket_key_len_var)
# server_socket_key_len_entry.pack()
#
# server_socket_password_label = ttk.Label(server_frame, text='password')
# server_socket_password_label.pack()
# server_socket_password_var = tk.StringVar(value='defaultPassword')
# server_socket_password_entry = ttk.Entry(server_frame, textvariable=server_socket_password_var)
# server_socket_password_entry.pack()


# decrypt file tab
decrypt_file_tab = ttk.Frame(notebook)
notebook.add(decrypt_file_tab, text='decrypt file')

file_path_var = tk.StringVar(value='')
file_path_label = ttk.Label(decrypt_file_tab, textvariable=file_path_var)
file_path_label.pack()

password_to_decrypt_file_label = ttk.Label(decrypt_file_tab, text='password to decrypt file')
password_to_decrypt_file_label.pack()
password_to_decrypt_file_var = tk.StringVar(value='defaultPassword')
password_to_decrypt_file_entry = ttk.Entry(decrypt_file_tab, textvariable=password_to_decrypt_file_var)
password_to_decrypt_file_entry.pack()

# key_length_to_decrypt_file_label = ttk.Label(decrypt_file_tab, text='key length to decrypt file 16, 24, 32')
# key_length_to_decrypt_file_label.pack()
# key_length_to_decrypt_file_var = tk.StringVar(value='16')
# key_length_to_decrypt_file_entry = ttk.Entry(decrypt_file_tab, textvariable=key_length_to_decrypt_file_var)
# key_length_to_decrypt_file_entry.pack()

key_length_to_decrypt_file_label = ttk.Label(decrypt_file_tab, text='key length to decrypt file 16, 24, 32')
key_length_to_decrypt_file_label.pack()

key_length_to_decrypt_file_var = tk.StringVar(value='16')
key_length_to_decrypt_file_combo = ttk.Combobox(decrypt_file_tab, textvariable=key_length_to_decrypt_file_var)
key_length_to_decrypt_file_combo.pack()
key_length_to_decrypt_file_combo["values"] = ("16", "24", "32")


def add_file_to_decrypt():
    file_path = filedialog.askopenfilename()
    file_path_var.set(file_path)
    print(file_path)


add_file_to_decrypt_btn = ttk.Button(decrypt_file_tab,
                                     text='add file to decrypt',
                                     command=lambda: add_file_to_decrypt())
add_file_to_decrypt_btn.pack(pady=20)


def decrypt_file_save_as():
    file = open(file_path_var.get(), 'rb')

    data = file.read()

    decrypted_data = decrypt(ciphertext=data,
                             password=password_to_decrypt_file_var.get(),
                             key_length=int(key_length_to_decrypt_file_var.get()))
    print(f'{password_to_decrypt_file_var.get()} {key_length_to_decrypt_file_var.get()}')

    decrypted_file = filedialog.asksaveasfile(mode='wb')
    decrypted_file.write(decrypted_data)


decrypt_file_save_as_btn = ttk.Button(decrypt_file_tab,
                                      text='decrypt file and save as',
                                      command=lambda: decrypt_file_save_as())
decrypt_file_save_as_btn.pack()

# run
window.mainloop()
