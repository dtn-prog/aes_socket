from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import tkinter.messagebox as messagebox


def encrypt(plaintext, password, key_length):
    salt = get_random_bytes(16)  #
    key = PBKDF2(password, salt, dkLen=key_length)  #
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return salt + iv + ciphertext


def decrypt(ciphertext, password, key_length):
    try:
        salt = ciphertext[:16]  # Extract the salt from the ciphertext
        iv = ciphertext[16:16 + AES.block_size]  # Extract the IV from the ciphertext
        ciphertext = ciphertext[16 + AES.block_size:]
        key = PBKDF2(password, salt, dkLen=key_length)  # Derive the key using the same salt
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return plaintext
    except ValueError:
        messagebox.showerror("Padding Error", "wrong password or key length")
        return None
