import aes, os
import tkinter as tk
import ttkbootstrap as ttk
from tkinter import filedialog
import tkinter.messagebox as messagebox

# text = b'Attack at dawn'
# key = os.urandom(16)
# iv = os.urandom(16)
# encrypted = aes.AES(key).encrypt_cbc(text, iv)
# decrypted = aes.AES(key).decrypt_cbc(encrypted, iv)
#
# print(f'encrypted: {encrypted}, decrypted: {decrypted}')

window = ttk.Window(themename='journal')
window.title('AES Encryption Mode CBC')
window.geometry('600x600')

file_path_to_encrypt_var = tk.StringVar(value='')
file_path_to_encrypt_label = ttk.Label(window, textvariable=file_path_to_encrypt_var)
file_path_to_encrypt_label.pack(pady=15)


def choose_file_to_encrypt():
    file_path = filedialog.askopenfilename()
    file_path_to_encrypt_var.set(file_path)


choose_file_to_encrypt_btn = ttk.Button(window,
                                        text='choose file to encrypt',
                                        command=lambda: choose_file_to_encrypt())
choose_file_to_encrypt_btn.pack()


def encrypt_file():
    if file_path_to_encrypt_var.get() == '':
        messagebox.showerror('error', 'no file chosen')
        return
    key = key_to_encrypt_var.get().encode()
    iv = iv_to_encrypt_var.get().encode()

    if len(key) not in [16, 24, 32]:
        messagebox.showerror('Error', 'Key must be 16, 24, or 32 bytes long')
        return

    if len(iv) != 16:
        messagebox.showerror('Error', 'IV must be 16 bytes long')
        return

    file_path = file_path_to_encrypt_var.get()
    file = open(file_path, 'rb')
    data = file.read()

    encrypted = aes.AES(key).encrypt_cbc(data, iv)

    saved_file = filedialog.asksaveasfile(mode='wb')
    saved_file.write(encrypted)


encrypt_file_btn = ttk.Button(window, text='encrypt file', command=lambda: encrypt_file())
encrypt_file_btn.pack(pady=15)

key_to_encrypt_var = tk.StringVar(value='1234567812345678')
key_to_encrypt_label = ttk.Label(text='key to encrypt, must be 16, 24 or 32 bytes long')
key_to_encrypt_label.pack()
key_to_encrypt_entry = ttk.Entry(window, textvariable=key_to_encrypt_var, width=35)
key_to_encrypt_entry.pack()

iv_to_encrypt_var = tk.StringVar(value='1234567812345678')
iv_to_encrypt_label = ttk.Label(text='iv must be 16 bytes long')
iv_to_encrypt_label.pack()
iv_to_encrypt_entry = ttk.Entry(window, textvariable=iv_to_encrypt_var, width=20)
iv_to_encrypt_entry.pack()

separator = ttk.Separator(window)
separator.pack(pady=10)

file_path_to_decrypt_var = tk.StringVar(value='')
file_path_to_decrypt_label = ttk.Label(window, textvariable=file_path_to_decrypt_var)
file_path_to_decrypt_label.pack()


def choose_file_to_decrypt():
    file_path = filedialog.askopenfilename()
    file_path_to_decrypt_var.set(file_path)


choose_file_to_decrypt_btn = ttk.Button(window,
                                        text='choose file to decrypt',
                                        command=lambda: choose_file_to_decrypt())
choose_file_to_decrypt_btn.pack()


def decrypt_file():
    if file_path_to_decrypt_var.get() == '':
        messagebox.showerror('Error', 'No file chosen')
        return

    key = key_to_decrypt_var.get().encode()
    iv = iv_to_decrypt_var.get().encode()

    if len(key) not in [16, 24, 32]:
        messagebox.showerror('Error', 'Key must be 16, 24, or 32 bytes long')
        return

    if len(iv) != 16:
        messagebox.showerror('Error', 'IV must be 16 bytes long')
        return

    file_path = file_path_to_decrypt_var.get()
    file = open(file_path, 'rb')
    data = file.read()
    file.close()

    decrypted = aes.AES(key).decrypt_cbc(data, iv)

    saved_file = filedialog.asksaveasfile(mode='wb')
    saved_file.write(decrypted)


decrypt_file_btn = ttk.Button(window, text='decrypt file', command=lambda: decrypt_file())
decrypt_file_btn.pack(pady=15)

key_to_decrypt_var = tk.StringVar(value='1234567812345678')
key_to_decrypt_label = ttk.Label(text='key to decrypt, must be 16, 24 or 32 bytes long')
key_to_decrypt_label.pack()
key_to_decrypt_entry = ttk.Entry(window, textvariable=key_to_decrypt_var, width=35)
key_to_decrypt_entry.pack()

iv_to_decrypt_var = tk.StringVar(value='1234567812345678')
iv_to_decrypt_label = ttk.Label(text='iv must be 16 bytes long')
iv_to_decrypt_label.pack()
iv_to_decrypt_entry = ttk.Entry(window, textvariable=iv_to_decrypt_var, width=20)
iv_to_decrypt_entry.pack()

window.mainloop()
