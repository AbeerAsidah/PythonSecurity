import socket
import json
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
from cryptography.hazmat.primitives import padding
import os
import secrets


# # Generate a random 16-byte key and IV
# encryption_key = os.urandom(16)
# iv = os.urandom(16)
def generate_key_iv(password, salt):
    # Ensure that the password is bytes
    if not isinstance(password, bytes):
        raise ValueError("Password must be of type bytes")

    key_material = hashlib.pbkdf2_hmac('sha256', password, salt, 100000, dklen=32+16)
    key = key_material[:32]
    iv = key_material[32:]
    return key, iv


# Server initialization
salt = os.urandom(16)  # Generate a random salt
password = secrets.token_bytes(16)  # Generate a random 16-byte password
key, iv = generate_key_iv(password, salt)



def decrypt_data(encrypted_data, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(base64.b64decode(encrypted_data.encode('utf-8'))) + decryptor.finalize()

    # Assuming you are using PKCS7 padding
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(decrypted_data) + unpadder.finalize()

def encrypt_data(data, key, iv):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data.encode('utf-8')) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(encrypted_data).decode('utf-8')

def send_request(request, key, iv):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('127.0.0.1', 12345))

    if 'password' in request:
        # Hash the password before sending it to the server
        hashed_password = hashlib.sha256(request['password'].encode('utf-8')).hexdigest()
        encrypted_password = encrypt_data(hashed_password, key, iv)
        request['password'] = encrypted_password

    client.send(json.dumps(request).encode('utf-8'))

    response = client.recv(1024).decode('utf-8')
    decrypted_response = decrypt_data(response, key, iv)
    print(f"Server response: {decrypted_response}")

    client.close()


def register(username, password):
    request = {"action": "register", "username": username, "password": password}
    send_request(request, key, iv)

def login(username, password):
    request = {"action": "login", "username": username, "password": password}
    send_request(request, key, iv)