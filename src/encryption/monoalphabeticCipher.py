import random

LETTERORDER = "abcdefghijklmnopqrstuvwxyz"

class MonoalphabeticCipher:

    keyCodex = {}

    def __init__(self):
        self.randomizeKey()

    def encrypt(self, text):

        ciphertext = ""

        for char in text:
            if char == " ":
                ciphertext += " "
            else:
                ciphertext += self.keyCodex[char]

        return ciphertext

    def decrypt(self, text, keyCodex=None):
        if not keyCodex:
            keyCodex = self.keyCodex

        decryptionCodex = {}
        for plainKey, cipherKey in keyCodex.items():
            decryptionCodex[cipherKey] = plainKey

        plaintext = ""

        for char in text:
            if char == " ":
                plaintext += " "
            else:
                plaintext += decryptionCodex[char]

        return plaintext

    def randomizeKey(self):
        randomizedAlpha = list(LETTERORDER)
        random.shuffle(randomizedAlpha)
        self.keyCodex = {}
        for index in range(len(randomizedAlpha)):
            self.keyCodex[LETTERORDER[index]] = randomizedAlpha[index]
    
    def evalProposedKey(self, text, proposedKey):

        keysCorrect = 0

        for key, mapping in proposedKey.items():
            if self.keyCodex[key] == mapping:
                keysCorrect += 1
        
        realPlaintext = self.decrypt(text)
        proposedPlaintext = self.decrypt(text, proposedKey)
        lettersCorrect = 0
        #print(realPlaintext)
        #print(proposedPlaintext)
        for letterPosition in range(len(realPlaintext)):
            if realPlaintext[letterPosition] != " " and realPlaintext[letterPosition] == proposedPlaintext[letterPosition]:
                lettersCorrect += 1

        return keysCorrect, lettersCorrect/len(realPlaintext)


if __name__ == "__main__":
    mon = MonoalphabeticCipher()
    plaintext = "testing this cipher scheme"
    ciphertext = mon.encrypt(plaintext)
    print(ciphertext)
    plaintext = mon.decrypt(ciphertext)
    print(plaintext)