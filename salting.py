import os

class Salt:
    def __init__(self):
        # Initialize class attributes and generate a random salt
        self.salt = os.urandom(16)

    def salt_password(self, password):
        # Combine the password and salt
        salted_password = password.encode('utf-8') + self.salt
        return salted_password