from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from test import generatekey

def encrypt(plain_text, key):
    cipher = AES.new(key, AES.MODE_CBC)
    cipher_text = cipher.encrypt(pad(plain_text.encode('utf-8'), AES.block_size))
    return cipher.iv + cipher_text

def decrypt(cipher_text, key):
    iv = cipher_text[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plain_text = unpad(cipher.decrypt(cipher_text[AES.block_size:]), AES.block_size)
    return plain_text.decode('utf-8')

key = generatekey()
with open('test.txt', 'r') as f:
    message = f.read()
print("Original Message:", message)

cipher_text = encrypt(message, key)
with open('encryped.txt', 'wb') as file:
    file.write(cipher_text)

decrypted_message = decrypt(cipher_text, key)
print("Decrypted Message:", decrypted_message)