# Password Security Program

## Overview

This Python program is designed to enhance the security of user accounts by implementing a range of robust security measures. It incorporates features such as password complexity checks, history tracking, multi-factor authentication (TOTP), salting, hashing, encryption, and account lockout settings.

## Features

- Password expiration with the option to update expired passwords.
- TOTP verification during login for multi-factor authentication.
- User-friendly prompts and informative messages.
- Sample user data set for testing and demonstration.
- Integration with AES encryption, salting, and hashing for enhanced security.

## Usage

1. Run the program.
2. Enter a valid user ID to manage your account's password security.
3. Follow the prompts to update expired passwords, check overall password security levels, and receive feedback for improvement.
4. Multi-factor authentication is enforced during login.
5. Optional features like salting can be applied for additional security.

## Disclaimer

This program is intended as a demonstration of password security practices and should not be used as a production-ready solution. Consult industry best practices and security experts for developing robust and secure authentication systems.

## Dependencies

- [Crypto library](https://pypi.org/project/pycryptodome/) for AES encryption.
- Custom modules: TermLoading, AESencrypt, salting, TOTP, hashing, UserData, complexity, and loading.

## Author

- Jungtae Kim

## Version

1.0

Enjoy using the Password Security Program for a safer and more secure online experience!

---

**Note:** Feel free to customize the author, date, version, and any other information based on your preferences.
