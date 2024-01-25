# File implementing encryption and decryption of the Caeser Cipher

import random

LETTERORDER = "abcdefghijklmnopqrstuvwxyz"
LETTERINDEX = {'a': 0, 'b': 1, 'c': 2, 'd': 3,
               'e': 4, 'f': 5, 'g': 6, 'h': 7,
               'i': 8, 'j': 9, 'k': 10, 'l': 11,
               'm': 12, 'n': 13, 'o': 14, 'p': 15,
               'q': 16, 'r': 17, 's': 18, 't': 19,
               'u': 20, 'v': 21, 'w': 22, 'x': 23,
               'y': 24, 'z': 25}

class CaeserCipher:

    key = None

    def __init__(self):
        self.randomizeKey()


    def encrypt(self, text):
        text = text.lower()
        ciphertext = ""
        for char in text:
            if char == " ":
                ciphertext += " "
            else:
                newAlphaIndex = (LETTERINDEX[char] + self.key) % 26
                ciphertext += LETTERORDER[newAlphaIndex]

        return ciphertext

    def decrypt(self, text, key=None):
        text = text.lower()
        plaintext = ""

        if not key:
            key = self.key

        decryptionKey = 26-key
        for char in text:
            if char == " ":
                plaintext += " "
            else:
                newAlphaIndex = (LETTERINDEX[char] + decryptionKey) % 26
                plaintext += LETTERORDER[newAlphaIndex]

        return plaintext

    def randomizeKey(self):
        # Note: We do not include 0 as a potential key because that would mean result in no encryption (plaintext = ciphertext)
        self.key = random.randint(1, 25)
