import socket
import json
import hashlib
import threading
import mysql.connector
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64
import os
import secrets

# Database configuration
db_config = {
    'host': 'localhost',
    'user': 'abeer2222',  # Replace with your MySQL username
    'password': '12aa12aa',  # Replace with your MySQL password
    'database': 'pythonsecurity'
}

# Establish a connection to the database
db_connection = mysql.connector.connect(**db_config)
db_cursor = db_connection.cursor()
# Database to store client information (including hashed passwords)
database = {}
exit_flag = False  # Flag to signal when to exit the server

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

def handle_client(client_socket, key, iv):
    try:
        request = client_socket.recv(1024).decode('utf-8')
        request_data = json.loads(request)

        if request_data["action"] == "login":
            username = request_data["username"]
            encrypted_password = request_data["password"]
            decrypted_password = decrypt_data(encrypted_password, key, iv)  # Use the shared key and IV

            # Fetch hashed password from the database
            db_cursor.execute("SELECT password FROM users WHERE username = %s", (username,))
            result = db_cursor.fetchone()

            if result:
                # User exists, verify the password
                stored_password = result[0]
                if verify_password(decrypted_password, stored_password):
                    response = {"status": "success", "message": "Login successful!"}
                else:
                    response = {"status": "failure", "message": "Invalid credentials."}
            else:
                response = {"status": "failure", "message": "Username not found. Do you want to create an account?"}

        elif request_data["action"] == "register":
            username = request_data["username"]
            decrypted_password = decrypt_data(request_data["password"], key, iv)  # Use the shared key and IV
            # Hash the password before storing it
            hashed_password = hash_password(decrypted_password)

            # Insert user information into the database
            db_cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)",
                              (username, hashed_password))
            db_connection.commit()

            response = {"status": "success", "message": "Account created successfully!"}
        else:
            response = {"status": "failure", "message": "Invalid action."}

        encrypted_response = encrypt_data(json.dumps(response), key, iv)  # Use the shared key and IV
        client_socket.send(encrypted_response.encode('utf-8'))

    except Exception as e:
        print(f"Error handling client request: {e}")
    finally:
        # Close the cursor and connection in a finally block
        if 'db_cursor' in locals():
            db_cursor.close()

        if 'db_connection' in locals() and db_connection.is_connected():
            db_connection.close()
            print("Database connection closed.")
        client_socket.close()

def hash_password(password):
    # Hash the password using a secure algorithm (e.g., SHA-256)
    hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
    return hashed_password
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


def verify_password(input_password, stored_password):
    # Verify the input password against the stored hashed password
    return hash_password(input_password) == stored_password


def start_server():
    global exit_flag
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', 12345))
    server.listen(5)
    print("Server is listening on port 12345...")

    while not exit_flag:
        try:
            client, addr = server.accept()
            print(f"Accepted connection from {addr}")

            client_handler = threading.Thread(target=handle_client, args=(client, key, iv))
            client_handler.start()
        except Exception as e:
            print(f"Error accepting client connection: {e}")

    print("Exiting the server.")
    server.close()

if __name__ == "__main__":
    try:
        start_server()
    except KeyboardInterrupt:
        exit_flag = True  # Set the flag when KeyboardInterrupt (Ctrl+C) is detected