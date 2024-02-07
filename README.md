# password_authentication_encryption
A Python program that has multiple functions related to password security.

## Password Expiration and history
According to the fictitious password policy, every password is set to expire every 6 months. Most 3 recent passwords are saved into the database and the user cannot use the password used already. 

## TOTP
Generates the Timed-based Token that is valid for 180 seconds to add multi-factor authentication.

## Password Complexity
The program first looks at these and then evaluates the complexity of the password. Then it determines the level of strength of the password.
- Password Length
- Lowercase Letter Usage
- Uppsercase Letter Usage
- Special Character Usage
- Number Digit Usage
- Should not have 3 consecutive numbers

## Salting
Adds randomized data to the password to enhance security by slowing down the speed of the brute force process and the rainbow attack.

## Hashing
Hashes the password to compare the hashed password value with the server instead of comparing the raw password.

## Encryption
Encrypts the password using AES Symmetric Cryptography to maintain confidentiality of the password.

## Account Lock policy
The account is locked after 5 failed login attempts. This is to protect the account from brute force attacks.
