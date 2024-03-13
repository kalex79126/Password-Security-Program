import hmac
import base64
import struct
import hashlib
import time
import secrets
import sys

class TOTP:
    def __init__(self):
        # Generate a random secret key
        self.secret = base64.b32encode(secrets.token_bytes(10)).decode('utf-8')

    def get_hotp_token(self, intervals_no):
        # Generate an HOTP (HMAC-based One-Time Password) token.
        # Args:
        #     intervals_no (int): The number of time intervals.
        # Returns:
        #     int: The HOTP token.
        key = base64.b32decode(self.secret, True)
        msg = struct.pack(">Q", intervals_no)
        h = hmac.new(key, msg, hashlib.sha1).digest()
        o = h[19] & 15
        h = (struct.unpack(">I", h[o:o + 4])[0] & 0x7fffffff) % 1000000
        return h

    def get_totp_token(self):
        # Generate a TOTP (Time-based One-Time Password) token.
        # Returns:
        #     str: The TOTP token.
        intervals_no = int(time.time()) // 30  # Time interval of 30 seconds
        x = str(self.get_hotp_token(intervals_no))
        while len(x) < 6:
            x += '0'
        return x

    def check_totp_expiration(self):
        # Check the expiration of the TOTP token.
        # Prints the generated TOTP and prompts the user to enter the TOTP within a 180-second window.
        # Exits the program if the TOTP is incorrect or the 180-second window elapses.
        # Generate TOTP
        correct_totp = self.get_totp_token()
        start_time = time.time()
        print(f"\nYour Generated TOTP: {correct_totp}")
        while True:
            # Get user input
            user_input = input("Enter TOTP: ")

            # Check if the entered TOTP is correct
            if user_input == correct_totp:
                print("Correct TOTP entered. Access granted!")
                break

            # Check if 180 seconds have passed
            current_time = time.time()
            elapsed_time = current_time - start_time

            if elapsed_time >= 180:
                print("TOTP has expired.")
                sys.exit()

            print("Incorrect TOTP. Try again.\n")
