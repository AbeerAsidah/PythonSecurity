from myProject.server import start_server
from myProject.client import register, login
import threading
import time

def main():
    # Run the server in a separate thread
    server_thread = threading.Thread(target=start_server)
    server_thread.start()

    # Simulate a delay before running the client (adjust as needed)
    time.sleep(2)

    while True:
        print("Choose an option:")
        print("1. Register a new account")
        print("2. Login")
        print("3. Exit")

        choice = input("Enter your choice (1, 2, or 3): ")

        if choice == "1":
            # Register a new user
            register_username = input("Enter username for registration: ")
            register_password = input("Enter password for registration: ")
            register(register_username, register_password)

        elif choice == "2":
            # Login with an existing user
            login_username = input("Enter username for login: ")
            login_password = input("Enter password for login: ")
            login(login_username, login_password)

        elif choice == "3":
            print("Exiting the program.")
            break

        else:
            print("Invalid choice. Please enter 1, 2, or 3.")

if __name__ == "__main__":
    main()
