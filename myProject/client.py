import socket
import json
import hashlib
import threading
import time

def send_request(request):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('127.0.0.1', 12345))

    if 'password' in request:
        # Hash the password before sending it to the server
        hashed_password = hashlib.sha256(request['password'].encode('utf-8')).hexdigest()
        request['password'] = hashed_password

    client.send(json.dumps(request).encode('utf-8'))

    response = client.recv(1024).decode('utf-8')
    print(f"Server response: {response}")

    client.close()

def register(username, password):
    request = {"action": "register", "username": username, "password": password}
    send_request(request)

def login(username, password):
    request = {"action": "login", "username": username, "password": password}
    send_request(request)
