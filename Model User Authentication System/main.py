from problem3 import EnrollmentSystem
from problem4 import LoginSystem

def main():
    PEPPER = "SuperSecretPepper"  # Secret pepper (store securely)

    # Initialize both systems
    enrollment_system = EnrollmentSystem(PEPPER)
    login_system = LoginSystem(PEPPER)

    print("Welcome to Just Invest!")
    while True:
        print("\nChoose an option:")
        print("1. Sign Up")
        print("2. Log In")
        print("3. Exit")

        choice = input("Enter your choice (1/2/3): ").strip()

        if choice == "1":
            print("\nSign Up")
            username = input("Enter your username: ")
            role = input("Enter your role (Client, PremiumClient, FinancialAdvisor, FinancialPlanner, or Teller): ")
            while True:
                password = input("Enter your password: ")
                try:
                    if enrollment_system.proactive_password_check(password, username):
                        enrollment_system.add_user(username, role, password)
                        print("User successfully signed up.")
                        break
                    else:
                        raise ValueError("Password does not meet the security requirements.")
                except ValueError as e:
                    print(f"Error: {e}")
                    print("Please try entering a stronger password.")

        elif choice == "2":
            print("\nLog In")
            username = input("Enter your username: ")
            password = input("Enter your password: ")

            if login_system.verify_password(username, password):
                print("\nLogin successful!")
                login_system.display_access_privileges(username)
            else:
                print("\nLogin failed. Invalid username or password.")

        elif choice == "3":
            print("\nExiting the system. Goodbye!")
            break

        else:
            print("\nInvalid choice. Please enter 1, 2, or 3.")

if __name__ == "__main__":
    main()
