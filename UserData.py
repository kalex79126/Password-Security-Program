class UserManager:
    def __init__(self, data):
        # Initialize the UserManager with user data.
        self.users_data = data

    def get_password_history(self, user_id):
        # Get the password history for a specific user ID.
        user = next((user for user in self.users_data if user['userID'] == user_id), None)
        if user:
            return user['history']
        else:
            return None

    def show_password_history(self, user_id):
        # Display the password history for a specific user ID.
        password_history = self.get_password_history(user_id)
        if password_history:
            return f"Password history for userID {user_id}: {password_history}"
        else:
            return f"User with user ID {user_id} not found."

    def get_current_password(self, user_id):
        # Get the current password for a specific user ID.
        user = next((user for user in self.users_data if user['userID'] == user_id), None)
        if user:
            return user['currentPassword']
        else:
            return None

    def show_current_password(self, user_id):
        # Display the current password for a specific user ID.
        password = self.get_current_password(user_id)
        if password:
            return f"Current password for userID {user_id}: {password}"
        else:
            return f"User with user ID {user_id} not found."

    def get_full_name(self, user_id):
        # Get the full name for a specific user ID.
        user = next((user for user in self.users_data if user['userID'] == user_id), None)
        if user:
            return f"{user['firstName']} {user['lastName']}"
        else:
            return None

    def get_expiration_month(self, user_id):
        # Get the expiration month for a specific user ID.
        user = next((user for user in self.users_data if user['userID'] == user_id), None)
        if user:
            return user['expirationMonthLeft']
        else:
            return None

    def get_account_status(self, user_id):
        # Get the account status for a specific user ID.
        user = next((user for user in self.users_data if user['userID'] == user_id), None)
        if user:
            return user['accountStatus']
        else:
            return None

    # Check if 'n' consecutive characters match between two strings.
    def has_consecutive_characters(self, password, target_string, n=4):
        for i in range(len(password) - n + 1):
            consecutive_chars = password[i:i + n]
            if consecutive_chars in target_string:
                return True
        return False

    # Check if the new password is similar to history/current.
    def is_password_similar_to_history(self, user_id, new_password):
        user = next((user for user in self.users_data if user['userID'] == user_id), None)
        if user:
            history = user['history']
            current_password = user['currentPassword']

            if (
                self.has_consecutive_characters(new_password, ''.join(history))
                or self.has_consecutive_characters(new_password, current_password)
                or self.has_consecutive_characters(current_password, new_password)
            ):
                return True  # Password has at least four consecutive characters in common with history or current password
            else:
                return False
        else:
            return False

    def set_new_password(self, user_id, new_password):
        # Set a new password for a specific user ID, considering security checks.
        if not self.is_password_similar_to_history(user_id, new_password):
            user = next((user for user in self.users_data if user['userID'] == user_id), None)
            if user:
                current_password = user['currentPassword']
                history = user['history']

                if current_password == new_password:
                    return "Password cannot be the same as the current password."

                if (
                    self.has_consecutive_characters(new_password, ''.join(history))
                    or self.has_consecutive_characters(new_password, current_password)
                    or self.has_consecutive_characters(current_password, new_password)
                ):
                    return "Password cannot be set. It contains at least four consecutive characters shared with the history or current password."

                return f"Password updated successfully for userID {user_id}."
            else:
                return f"User with user ID {user_id} not found."
        else:
            return "Password cannot be set. It contains at least four consecutive characters shared with the history or current password."
