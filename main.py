# Password Security Program
#
# This Python program implements a comprehensive set of account security measures, covering password complexity checks,
# password history tracking, multi-factor authentication using TOTP (Time-based One-Time Password), salting, hashing,
# encryption, and account lockout settings. It actively interacts with user data, enforces password expiration policies,
# and employs security protocols to enhance the overall protection of user accounts.
#
# The program includes a sample user data set containing details such as expiration periods, password histories, and account statuses.
# The core functionality is encapsulated in the PasswordSecurityManager class, which manages user password security operations like updating
# passwords, encrypting, salting, hashing, and enforcing TOTP verification during login.
#
# To optimize efficiency and readability, the code is structured according to Python naming conventions. User inputs undergo validation,
# and the program delivers informative messages on login attempts and password updates.
#
# External Dependencies:
# - Crypto library for AES encryption
# - TermLoading, AESencrypt, salting, TOTP, hashing, UserData, complexity, and loading modules for specific functionalities
# - sys and time modules for system-related operations and time delays
#
# Usage:
# Run the program, enter a valid user ID, and follow the prompts to manage your account's password security. The program guides users
# through updating expired passwords, checks overall password security levels, and provides feedback for improvement. Multi-factor
# authentication is enforced during login, and optional features like salting can be applied for additional security.
#
# Disclaimer:
# This program serves as a demonstration of password security practices and should not be used as a production-ready solution. It
# is advised to consult industry best practices and security experts for developing robust and secure authentication systems.
#
# Author: Jungtae Kim
# Date: March 13, 2024
# Version: 1.0
#
# Enjoy using the Password Security Program for a safer and more secure online experience!



from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
from AESencrypt import AESCipher
from salting import salt
from TOTP import TOTP
from hashing import SHA256Hasher
from UserData import UserManager
from complexity import PasswordSecurityChecker
from loading import TermLoading
import sys, time

# Sample user data set with expiration periods, password histories, and account statuses
sample_users_data = [
    {
        "userID": 1,
        "firstName": "Jane",
        "lastName": "Doe",
        "history": ["R#2p$L@9x!", "Sunshine4@", "BlueSky12#"],
        "expirationMonthLeft": 0,
        "currentPassword": "JaneDoe@2024!",
        "accountStatus": "Active"
    },
    {
        "userID": 2,
        "firstName": "John",
        "lastName": "Smith",
        "history": ["P@ssw0rd!", "Grapes&Apples#", "Security123"],
        "expirationMonthLeft": 2,
        "currentPassword": "Smith#Secure123",
        "accountStatus": "Active"
    },
    {
        "userID": 3,
        "firstName": "Alice",
        "lastName": "Johnson",
        "history": ["PurpleSun$et", "Mountain@Top67", "OceanWaves!"],
        "expirationMonthLeft": 5,
        "currentPassword": "Alic3@Wav3s!2024",
        "accountStatus": "Active"
    }
]

# Common passwords data
common_passwords = [
    "password", "123456", "qwerty", "admin", "letmein",
    "welcome", "1234", "12345", "abc123", "123abc",
    "password1", "password123", "123qwe", "qwerty123",
    "iloveyou", "sunshine", "123321", "qwertyuiop", "admin123",
    "password!", "123!abc", "passw0rd", "secret", "football",
    "qwerty12345", "123!@#qwe", "test123", "123qwe!@#",
    "trustno1", "hello123", "monkey", "superman", "letmein123",
    "123!@#qweQAZ", "asdfgh", "123abc!", "welcome123", "pass123",
    "qazwsx", "letmein!", "1q2w3e", "1234abcd", "abc123!",
    "password12", "pass1234", "adminadmin", "12345qwert", "qwert12345",
    "abcdef", "password1234", "password12345", "admin1234", "password!",
]

# A class that contains multiple functions regarding user password security
class PasswordSecurityManager:
    def __init__(self, user_id, data, common_passwords):
        self.user_id = user_id
        self.common_passwords = common_passwords
        self.encryption = AESCipher()
        self.salter = salt()
        self.totp = TOTP()
        self.hash = SHA256Hasher()
        self.user_manager = UserManager(data)
        self.password_checker = PasswordSecurityChecker("", self.common_passwords)
        self.users_data = sample_users_data

    def get_user_password(self):
        # Get the current password for the selected user ID.
        return self.user_manager.get_current_password(self.user_id)
    
    def check_password_age(self):
        # Check the time left until the expiration month.  
        return self.user_manager.get_expiration_month(self.user_id)

    def update_password_if_expired(self):
        # Require the user to update the password if it's expired.    
        expiration_month = self.check_password_age()
        if expiration_month == 0:
            new_password = input("\nYour password has expired. Enter a new password: ")

            current_password_at_start = self.get_user_password()
            result = self.user_manager.set_new_password(self.user_id, new_password)
            
            # Update the user data in sample_users_data.
            if "successfully" in result:            
                for user in self.user_manager.users_data:
                    if user['userID'] == self.user_id:
                        user['history'] = [current_password_at_start] + user['history'][:2]
                        user['expirationMonthLeft'] = 6
                        user['currentPassword'] = new_password
                        break

            print(result)

    def encrypt_bytes(self, plaintext):
        # Encrypt bytes.
        return self.encryption.encrypt_bytes(plaintext)

    def encrypt_strings(self, plaintext):
        # Encrypt strings.   
        return self.encryption.encrypt_string(plaintext)
    
    def salt_and_store_password(self, get_user_password):
        # Add salt to the password.      
        return self.salter.salt_password(get_user_password)
    
    def hash_bytes(self, get_user_password_hash):
        # Hash bytes.
        return self.hash.hash_bytes(get_user_password_hash)
        
    def hash_string(self, get_user_password):
        # Hash string.
        return self.hash.hash_string(get_user_password)
    
    def get_hashed_password(self):
        # Get the hashed password.
        return self.hash.get_hashed_string()
        
    def generate_totp(self):
    # Generate TOTP (Time-based One-Time Password) that is live for 180 seconds, then require the user to enter the TOTP correctly.
        self.totp.check_totp_expiration()

    def check_password_security(self, get_user_password):
    # Evaluate the overall security level of the current user password.
        self.password_checker.password = get_user_password
        return self.password_checker.security_level()

    def provide_password_feedback(self):
    # Provide feedback regarding the current user password security.
        return self.password_checker.feedback_on_improvement()




def get_user_id():
    # Get valid input for user ID.
    while True:
        user_id = input("Enter your user ID: ")
        if user_id.isdigit() and int(user_id) <= 3:
            return int(user_id)
        print("Invalid ID. Please enter a valid numeric ID.")




if __name__ == '__main__':
    user_id = get_user_id()

    # Create a new class instance with user ID input.
    password_manager = PasswordSecurityManager(user_id, sample_users_data, common_passwords)
    password = password_manager.get_user_password()
    animation = TermLoading()
    # print(password)

    # Ask the user to type in the current password.
    # Account is locked after 5 failed login attempts to prevent brute force attack.
    login_attempt = 0

    while login_attempt < 5:
        user_pw = input("Enter your Password: ")
        login_attempt += 1 
   
        if user_pw == password:
            animation.show('Verifying Login Account Information...', failed_message='', finish_message="Login success!")
            time.sleep(3)
            animation.finished = True

            # A user has to enter TOTP generated by the program within 180 seconds.
            password_manager.generate_totp()
            break
        print(f"Failed to login. \nFailed Login Attempt: {login_attempt}\n")

    if login_attempt == 5:
        print("Unable to login. Account is Disabled due to 5 failed login attempts.\nTerminating System...")
        sys.exit()

    # If the password has been expired, then ask to create a new password.
    while True:
        password_manager.update_password_if_expired()
        if password_manager.check_password_age() != 0:
            break

    # Load updated password 
    password = password_manager.get_user_password()

    animation.show('Evaluating Security Level for your Current Password...', failed_message='', finish_message="")
    time.sleep(3)
    animation.finished = True

    # Evaluate the security level and provide feedback for the current user password 
    security_level = password_manager.check_password_security(password)
    improvement_feedback = password_manager.provide_password_feedback()

    print("---------------------------------------------------------")
    print(f"\nYour Current Password Security Level: {security_level}")
    print("\nImprovement Feedback:")
    for feedback in improvement_feedback:
        print(f"- {feedback}")
    print("\n---------------------------------------------------------")

    # Store hash value for current user password.
    password_manager.hash_string(password)
    hashed_password = password_manager.get_hashed_password()

    while True:
        salt_request = input("\nWould you like to add salt to your password? (y / n) ")
        if salt_request == "y" or salt_request == "n":
            break
        print("Invalid input.")

    # An option to apply salting before encrypting the password to slow down the brute force process.
    animation.show('Applying Security to Password...', failed_message='')
    time.sleep(3)
    animation.finished = True
    if salt_request == "y":
        salted_password = password_manager.salt_and_store_password(password)
        print(f"\nYour password has been successfully salted!")
        time.sleep(2)
        print(f"\nSalted Password: {salted_password}")    
        # Encrypt the password using AES for confidentiality.
        cipher = password_manager.encrypt_bytes(salted_password)
        time.sleep(2)
        print(f"Encrypted Password: {cipher}")

    elif salt_request == "n":
        # An option to encrypt the password without applying salting.
        cipher = password_manager.encrypt_strings(password)
        time.sleep(2)
        print(f"\nEncrypted Password: {cipher}")

    # Store hash value for encrpyted user password.
    password_manager.hash_bytes(cipher)
    hashed_encrypted_password = password_manager.get_hashed_password()
    time.sleep(2)
    print(f"Raw Password Hash: {hashed_password}")
    time.sleep(2)
    print(f"Encrypted Password Hash: {hashed_encrypted_password}")
