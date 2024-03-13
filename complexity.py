import re
import bisect

class PasswordSecurityChecker:
    def __init__(self, password, common_passwords):
        # Initialize PasswordSecurityChecker with the given password and common passwords list
        self.password = password
        self.common_passwords = common_passwords

    def check_length(self, min_length=8):
        # Check if the password meets the minimum length requirement
        return len(self.password) >= min_length

    def check_uppercase(self):
        # Check if the password contains at least one uppercase letter
        return any(char.isupper() for char in self.password)

    def check_lowercase(self):
        # Check if the password contains at least one lowercase letter
        return any(char.islower() for char in self.password)

    def check_digit(self):
        # Check if the password contains at least one digit
        return any(char.isdigit() for char in self.password)

    def check_special_character(self):
        # Check if the password contains at least one special character
        special_characters = "!@#$%^&*()-_=+[]{}|;:'\",.<>/?`~"
        return any(char in special_characters for char in self.password)

    def find_next(self, x, a):
        # Find the next element in the list x greater than a
        i = bisect.bisect_right(x, a)
        if i < len(x):
            return x[i]
        return None

    def is_sequence(self, x):
        # Check if the elements in the list x form a sequence (ascending or descending)
        for i in range(len(x) - 1):
            next_char = self.find_next(x, x[i])
            if next_char and ((x[i].isdigit() and next_char.isdigit() and (int(x[i]) + 1 == int(next_char) or int(x[i]) - 1 == int(next_char)))):
                return False
        return True

    def extract_consecutive_numbers(self):
        # Extract 3 or more consecutive numbers from the password
        pattern = re.compile(r'(\d{3,})')
        matches = re.findall(pattern, self.password)
        return [match for match in matches]

    def extract_consecutive_letters(self, min_length):
        # Extract consecutive letters of at least min_length from the password
        pattern = re.compile(r'([a-zA-Z]{%d,})' % min_length)
        matches = re.findall(pattern, self.password)
        return [match.lower() for match in matches]

    def check_number_sequence(self):
        # Check if the password contains sequences of three or more consecutive numbers
        extracted_numbers = self.extract_consecutive_numbers()

        if not extracted_numbers:
            return True

        results = [self.is_sequence(number) for number in extracted_numbers]
        return any(results)

    def check_consecutive_letters(self, min_length=4):
        # Check if the password contains sequences of consecutive letters from common passwords
        extracted_letters = self.extract_consecutive_letters(min_length)

        for common_password in self.common_passwords:
            common_password_lower = common_password.lower()
            for substring in extracted_letters:
                # Check if at least min_length consecutive letters match with any part of the common password
                for i in range(len(substring) - min_length + 1):
                    if common_password_lower.find(substring[i:i+min_length]) != -1:
                        return False

        return True

    def check_consecutive_qwerty(self):
        # Check if the password contains sequences of consecutive letters from common QWERTY sequences
        qwerty_sequences = ['qwerty', 'asdfgh', 'zxcvbn', 'poiuyt', 'lkjhgf', 'mnbvcx']
        extracted_letters = self.extract_consecutive_letters(min_length=3)

        for sequence in qwerty_sequences:
            for substring in extracted_letters:
                # Check if at least 3 consecutive letters match with any part of the QWERTY sequence or its reverse
                for i in range(len(substring) - 2):
                    if sequence.lower().find(substring[i:i+3]) != -1 or sequence.lower()[::-1].find(substring[i:i+3]) != -1:
                        return False

        return True

    def check_complexity(self):
        # Check overall complexity of the password
        return self.check_uppercase() and self.check_lowercase() and self.check_digit() and self.check_special_character()

    def check_consecutive_characters(self):
        # Check for consecutive character patterns in the password
        return (
            self.check_number_sequence()
            and self.check_consecutive_letters()
            and self.check_consecutive_qwerty()
        )

    def security_level(self):
        # Determine the security level of the password based on various checks
        length_check = self.check_length()
        complexity_check = self.check_complexity()
        consecutive_characters_check = self.check_consecutive_characters()

        if length_check and complexity_check and consecutive_characters_check:
            return "Very Strong"
        elif length_check and complexity_check:
            return "Strong"
        elif length_check or complexity_check:
            return "Moderate"
        else:
            return "Weak"

    def feedback_on_improvement(self):
        # Provide feedback on how to improve the password strength
        feedback = []

        if not self.check_uppercase():
            feedback.append("Add an uppercase letter.")
        if not self.check_lowercase():
            feedback.append("Add a lowercase letter.")
        if not self.check_digit():
            feedback.append("Add a digit.")
        if not self.check_special_character():
            feedback.append("Add a special character.")
        if not self.check_number_sequence():
            feedback.append("Avoid using 3 consecutive numbers.")
        if not self.check_consecutive_letters():
            feedback.append("Avoid using 4 consecutive letters from common passwords.")
        if not self.check_consecutive_qwerty():
            feedback.append("Avoid using 3 consecutive letters from the QWERTY keyboard.")

        return feedback if self.security_level() != "Very Strong" else []

if __name__ == "__main__":
    test_password = "asdfg123"
    sample_passwords = [
        "P@ssw0rd",
        "password123",
        "123456",
        "abcdef",
        "Secure12",
        "!2aBcDeFgH",
        "qwerty123",
        "asdfg123",
        "abc123def",
        "!@#$%^&*",
    ]
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

    checker = PasswordSecurityChecker(test_password, common_passwords)

    print(f"\nPassword Length Check: {checker.check_length()}")
    print(f"Password Complexity Check: {checker.check_complexity()}")
    print(f"Consecutive Numbers Check: {checker.check_number_sequence()}")
    print(f"Consecutive Letters Check: {checker.check_consecutive_letters()}")
    print(f"Consecutive QWERTY Check: {checker.check_consecutive_qwerty()}")
    print(f"\nOverall Security Level: {checker.security_level()}")

    if not checker.check_complexity():
        improvement_feedback = checker.feedback_on_improvement()
        print("\nImprovement Feedback:")
        for feedback in improvement_feedback:
            print(f"- {feedback}")
