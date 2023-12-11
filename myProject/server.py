import socket
import json
import hashlib
import threading
import mysql.connector

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
#
# def handle_client(client_socket):
#     try:
#         request = client_socket.recv(1024).decode('utf-8')
#         request_data = json.loads(request)
#
#         if request_data["action"] == "login":
#             username = request_data["username"]
#             password = request_data["password"]
#
#             if username in database:
#                 # User exists, verify the password
#                 if verify_password(password, database[username]["password"]):
#                     response = {"status": "success", "message": "Login successful!"}
#                 else:
#                     response = {"status": "failure", "message": "Invalid credentials."}
#             else:
#                 response = {"status": "failure", "message": "Username not found. Do you want to create an account?"}
#
#         elif request_data["action"] == "register":
#             username = request_data["username"]
#             password = request_data["password"]
#
#             if username not in database:
#                 # Hash the password before storing it
#                 hashed_password = hash_password(password)
#                 database[username] = {"password": hashed_password}
#                 response = {"status": "success", "message": "Account created successfully!"}
#             else:
#                 response = {"status": "failure", "message": "Username already exists."}
#
#         else:
#             response = {"status": "failure", "message": "Invalid action."}
#
#         client_socket.send(json.dumps(response).encode('utf-8'))
#     except Exception as e:
#         print(f"Error handling client request: {e}")
#     finally:
#         client_socket.close()
def handle_client(client_socket):
    try:
        request = client_socket.recv(1024).decode('utf-8')
        request_data = json.loads(request)

        if request_data["action"] == "login":
            username = request_data["username"]
            password = request_data["password"]

            # Fetch hashed password from the database
            db_cursor.execute("SELECT password FROM users WHERE username = %s", (username,))
            result = db_cursor.fetchone()

            if result:
                # User exists, verify the password
                stored_password = result[0]
                if verify_password(password, stored_password):
                    response = {"status": "success", "message": "Login successful!"}
                else:
                    response = {"status": "failure", "message": "Invalid credentials."}
            else:
                response = {"status": "failure", "message": "Username not found. Do you want to create an account?"}

        elif request_data["action"] == "register":
            username = request_data["username"]
            password = request_data["password"]

            # Hash the password before storing it
            hashed_password = hash_password(password)

            # Insert user information into the database
            db_cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)",
                              (username, hashed_password))
            db_connection.commit()

            response = {"status": "success", "message": "Account created successfully!"}
        else:
            response = {"status": "failure", "message": "Invalid action."}

        client_socket.send(json.dumps(response).encode('utf-8'))

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

            client_handler = threading.Thread(target=handle_client, args=(client,))
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

