import hashlib
import os
import hmac


class LoginSystem:
    def __init__(self, pepper, password_file="passwd.txt"):
        """
        Initialize the Login System.
        :param pepper: The secret pepper value.
        :param password_file: The file storing user records.
        """
        self.pepper = pepper
        self.password_file = password_file

        # Access control policy mapping roles to permissions
        self.access_control_policy = {
            "Client": ["View Account Balance", "View Portfolio", "View Advisor Contact"],
            "PremiumClient": [
                "View Account Balance",
                "View Portfolio",
                "View Advisor Contact",
                "Modify Portfolio",
            ],
            "FinancialAdvisor": [
                "View Account Balance",
                "View Portfolio",
                "Modify Portfolio",
                "View Private Instruments",
            ],
            "FinancialPlanner": [
                "View Account Balance",
                "View Portfolio",
                "Modify Portfolio",
                "View Private Instruments",
                "View Money Market Instruments",
            ],
            "Teller": ["Limited Access (Business Hours Only)"],
        }

    def retrieve_user(self, username):
        """
        Retrieve a user's record from the password file.
        :param username: The username to retrieve.
        :return: A dictionary with user details if found, None otherwise.
        """
        if not os.path.exists(self.password_file):
            print("Password file not found. Please enroll users first.")
            return None

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

    def hash_password(self, password, salt):
        """
        Hash a password using SHA3-384 with salt and pepper.
        :param password: The plaintext password.
        :param salt: The unique salt for the password.
        :return: The hashed password.
        """
        combined = password.encode('utf-8') + salt + self.pepper.encode('utf-8')
        return hashlib.sha3_384(combined).hexdigest()

    def verify_password(self, username, password):
        """
        Verify a user's password.
        :param username: The username.
        :param password: The plaintext password to check.
        :return: True if the password matches, False otherwise.
        """
        user_record = self.retrieve_user(username)
        if not user_record:
            print(f"User '{username}' not found.")
            return False

        # Retrieve salt and stored hash
        salt = user_record["salt"]
        stored_hash = user_record["hashed_password"]

        # Hash the input password with the retrieved salt and pepper
        hashed_input = self.hash_password(password, salt)

        # Compare the stored hash with the input hash
        return hmac.compare_digest(hashed_input, stored_hash)

    def display_access_privileges(self, username):
        """
        Display the access privileges for a given user.
        :param username: The username.
        """
        user_record = self.retrieve_user(username)
        if not user_record:
            print(f"User '{username}' not found.")
            return

        role = user_record["role"]
        print(f"\nAccess Privileges for {username}:")
        print(f"Role: {role}")
        print("Permissions:")
        for permission in self.access_control_policy.get(role, []):
            print(f" - {permission}")


if __name__ == "__main__":
    # Secret pepper (store securely)
    PEPPER = "SuperSecretPepper"

    # Initialize the Login System
    login_system = LoginSystem(PEPPER)

    # Simple login interface
    print("Welcome to the Login System")
    username = input("Enter your username: ")
    password = input("Enter your password: ")

    if login_system.verify_password(username, password):
        print("\nLogin successful!")
        login_system.display_access_privileges(username)
    else:
        print("\nLogin failed. Invalid username or password.")
