import re
import hashlib
import os
import hmac

class EnrollmentSystem:
    def __init__(self, pepper, password_file="passwd.txt", weak_password_file="weak_passwords.txt"):
        """
        Initialize the Sign Up System with salt and pepper hashing.
        :param pepper: The secret pepper value.
        :param password_file: The file to store user records.
        :param weak_password_file: The file containing weak passwords.
        """
        self.pepper = pepper
        self.password_file = password_file
        self.weak_password_file = weak_password_file

        # Create the password file if it does not exist
        if not os.path.exists(self.password_file):
            with open(self.password_file, 'w') as f:
                pass

        # Ensure the weak password file exists
        if not os.path.exists(self.weak_password_file):
            with open(self.weak_password_file, 'w') as f:
                f.write("123456\npassword\n123456789\nqwerty\n12345\n")

    def load_weak_passwords(self):
        """Load weak passwords from the file."""
        with open(self.weak_password_file, 'r') as f:
            return set(line.strip() for line in f)

    def generate_salt(self):
        """Generates a unique salt for a password."""
        return os.urandom(16)  # Generate 16-byte random salt

    def hash_password(self, password, salt):
        """
        Hash a password using salt and pepper.
        :param password: The plaintext password.
        :param salt: The unique salt for the password.
        :return: The hashed password.
        """
        combined = password.encode('utf-8') + salt + self.pepper.encode('utf-8')
        return hashlib.sha3_384(combined).hexdigest()

    def proactive_password_check(self, password, username):
        """
        Check if the password meets the security requirements.
        :param password: The plaintext password.
        :param username: The username of the user.
        :return: True if the password is strong, False otherwise.
        """
        weak_passwords = self.load_weak_passwords()

        # Password policy
        if (
            8 <= len(password) <= 12
            and re.search(r"[A-Z]", password)
            and re.search(r"[a-z]", password)
            and re.search(r"\d", password)
            and re.search(r"[!@#$%*&]", password)
            and password not in weak_passwords
            and password != username
        ):
            return True
        return False

    def add_user(self, username, role, password):
        """
        Enroll a new user in the system.
        :param username: The username.
        :param role: The user's role.
        :param password: The plaintext password.
        """
        # Generate a salt and hash the password
        salt = self.generate_salt()
        hashed_password = self.hash_password(password, salt)

        # Store the user information
        with open(self.password_file, 'a') as f:
            f.write(f"{username}:{role}:{salt.hex()}:{hashed_password}\n")

        print(f"User '{username}' enrolled successfully.")

    def retrieve_user(self, username):
        """
        Retrieve a user's record from the password file.
        :param username: The username to retrieve.
        :return: A dictionary with the user's details if found, None otherwise.
        """
        with open(self.password_file, 'r') as f:
            for line in f:
                user, role, salt, hashed_password = line.strip().split(":")
                if user == username:
                    return {
                        "username": user,
                        "role": role,
                        "salt": bytes.fromhex(salt),
                        "hashed_password": hashed_password,
                    }
        return None


if __name__ == "__main__":
    # Secret pepper (store securely)
    PEPPER = "SuperSecretPepper"

    # Initialize the Enrollment System
    system = EnrollmentSystem(PEPPER)

    # Simple signup interface
    print("Welcome! Sign Up to Just Invest")
    username = input("Enter your username: ")
    role = input("Enter your role (Client, PremiumClient, FinancialAdvisor, FancialPlanner or Teller): ")

    # Prompt for password and validate it
    while True:
        password = input("Enter your password: ")
        try:
            if system.proactive_password_check(password, username):
                system.add_user(username, role, password)
                print("User successful signed up.")
                break
            else:
                raise ValueError("Password does not meet the security requirements.")
        except ValueError as e:
            print(f"Error: {e}")
            print("Please try entering a stronger password.")
