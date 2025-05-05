import hashlib
import os
import hmac

class SaltPepperHashing:
    def __init__(self, pepper, password_file="passwd.txt"):
        """
        Initialize the Salt and Pepper hashing mechanism with a password file.
        :param pepper: The secret pepper value.
        :param password_file: The file to store user records.
        """
        self.pepper = pepper
        self.password_file = password_file

        # Create the password file if it does not exist
        if not os.path.exists(self.password_file):
            with open(self.password_file, 'w') as f:
                pass

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
        # Combine password, salt, and pepper
        combined = password.encode('utf-8') + salt + self.pepper.encode('utf-8')
        hashed = hashlib.sha3_384(combined).hexdigest()
        return hashed

    def add_user(self, username, role, password):
        """
        Add a new user to the password file.
        :param username: The username.
        :param role: The user's role.
        :param password: The plaintext password.
        """
        # Generate a salt for the user
        salt = self.generate_salt()
        # Hash the password with the salt and pepper
        hashed_password = self.hash_password(password, salt)

        # Write the user record to the password file
        with open(self.password_file, 'a') as f:
            f.write(f"{username}:{role}:{salt.hex()}:{hashed_password}\n")

        print(f"User '{username}' added with role '{role}'.")

    def retrieve_user(self, username):
        """
        Retrieve a user's record from the password file.
        :param username: The username to retrieve.
        :return: A dictionary with user's details if found, None otherwise.
        """
        with open(self.password_file, 'r') as f:
            for line in f:
                user, role, salt, hashed_password = line.strip().split(":")
                if user == username:
                    return {
                        "username": user,
                        "role": role,
                        "salt": bytes.fromhex(salt),
                        "hashed_password": hashed_password
                    }
        return None

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


# Test
if __name__ == "__main__":
    # Define a secret pepper (store this securely in your application, not in the code)
    PEPPER = "SuperSecretPepper"

    # Create an instance of the SaltPepperHashing class
    sp_hashing = SaltPepperHashing(PEPPER)

    # Add users
    sp_hashing.add_user("Sasha Kim", "Client", "Secure@123")
    sp_hashing.add_user("Noor Abbasi", "PremiumClient", "Strong$Pass1")

    # Retrieve user records
    print("\nRetrieve Records:")
    record = sp_hashing.retrieve_user("Sasha Kim")
    print(record)

    # Verify passwords
    print("\nPassword Verification:")
    print(f"Correct password for Sasha Kim: {sp_hashing.verify_password('Sasha Kim', 'Secure@123')}")
    print(f"Incorrect password for Noor Abbasi: {sp_hashing.verify_password('Noor Abbasi', 'WrongPass')}")
