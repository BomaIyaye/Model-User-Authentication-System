class RBACSystem:
    def __init__(self):
        # Define roles and their permissions
        self.roles = {
            "Client": ["view_account_balance", "view_portfolio", "view_advisor_contact"],
            "PremiumClient": ["view_account_balance", "view_portfolio", "view_advisor_contact", "modify_portfolio"],
            "FinancialAdvisor": ["view_account_balance", "view_portfolio", "modify_portfolio", "view_private_instruments"],
            "FinancialPlanner": ["view_account_balance", "view_portfolio", "modify_portfolio", "view_private_instruments", "view_money_market"],
            "Teller": ["limited_access"]
        }
        # Define users and their assigned roles
        self.users = {}

    def add_user(self, username, role):
        if role not in self.roles:
            raise ValueError(f"Role '{role}' is not defined.")
        self.users[username] = role
        print(f"User '{username}' added with role '{role}'.")

    def check_permission(self, username, permission):
        role = self.users.get(username)
        if not role:
            raise ValueError(f"User '{username}' not found.")
        if permission in self.roles[role]:
            return True
        return False

    def display_permissions(self, username):
        role = self.users.get(username)
        if not role:
            raise ValueError(f"User '{username}' not found.")
        return self.roles[role]


# Example Usage
if __name__ == "__main__":
    # Instantiate the RBAC system
    rbac = RBACSystem()

    # Add users and assign roles
    rbac.add_user("Sasha Kim", "Client")
    rbac.add_user("Noor Abbasi", "PremiumClient")
    rbac.add_user("Mikael Chen", "FinancialAdvisor")
    rbac.add_user("Ellis Nakamura", "FinancialPlanner")
    rbac.add_user("Alex Hayes", "Teller")

    # Check permissions
    print("\nPermission Checks:")
    print(f"Sasha Kim can view portfolio: {rbac.check_permission('Sasha Kim', 'view_portfolio')}")
    print(f"Noor Abbasi can modify portfolio: {rbac.check_permission('Noor Abbasi', 'modify_portfolio')}")
    print(f"Mikael Chen can view private instruments: {rbac.check_permission('Mikael Chen', 'view_private_instruments')}")
    print(f"Alex Hayes has limited access: {rbac.check_permission('Alex Hayes', 'limited_access')}")
    print(f"Ellis Nakamura can view money market: {rbac.check_permission('Ellis Nakamura', 'view_money_market')}")

    # Display permissions for a user
    print("\nUser Permissions:")
    print(f"Permissions for Noor Abbasi: {rbac.display_permissions('Noor Abbasi')}")
    print(f"Permissions for Alex Hayes: {rbac.display_permissions('Alex Hayes')}")
  