from jakobsensAlgorithm import jakobsensAlgorithm, initializeExpectationMatrix
from src.utils.utils import selectPlainText
from src.encryption.monoalphabeticCipher import MonoalphabeticCipher
import random

def generateInitialKey():
    key = {}
    LETTERORDER = "abcdefghijklmnopqrstuvwxyz"
    SELECTORDER = list(LETTERORDER)

    random.shuffle(SELECTORDER)

    for i in range(len(LETTERORDER)):
        key[LETTERORDER[i]] = SELECTORDER[i]

    return key

if __name__ == "__main__":

    lettersCorrect = []
    plaintextCorrect = []
    plaintextWords = 50
    spacesRemoved = True
    numKeys = 3

    for i in range(100):

        # Generating and getting plaintext
        plaintext = selectPlainText(plaintextWords)
        if spacesRemoved:
            plaintext = plaintext.replace(" ", "")

        # Creating cipher object and generating ciphertext
        cipher = MonoalphabeticCipher()
        ciphertext = cipher.encrypt(plaintext)

        # Generating the expected distribution matrix
        expectedDist = initializeExpectationMatrix(len(ciphertext), plaintextWords, spacesRemoved=spacesRemoved)

        maxPlaintextCorrect = -1
        maxLettersCorrect = -1
        maxDerivedKey = None
        for i in range(numKeys):
            initialKey = generateInitialKey()
            initialPunativePlaintext = cipher.decrypt(ciphertext, initialKey)
            
            derivedKey = jakobsensAlgorithm(ciphertext, initialKey, initialPunativePlaintext, expectedDist, spacesRemoved=spacesRemoved)

            newLettersCorrect, newPlaintextCorrect = cipher.evalProposedKey(ciphertext, derivedKey)

            if maxPlaintextCorrect < newPlaintextCorrect:
                maxDerivedKey = derivedKey
                maxPlaintextCorrect = newPlaintextCorrect

        print("\nFinal", cipher.evalProposedKey(ciphertext, maxDerivedKey))

        print("Correct Keys:")
        realKey = cipher.keyCodex
        for key, val in maxDerivedKey.items():
            if realKey[key] == val:
                print(val, end = " ")
        print("")

        newLettersCorrect, newPlaintextCorrect = cipher.evalProposedKey(ciphertext, maxDerivedKey)
        lettersCorrect.append(newLettersCorrect)
        plaintextCorrect.append(newPlaintextCorrect)


    print("Average Letters Correct:", sum(lettersCorrect)/len(lettersCorrect))
    print("Average Plaintext Correct:", sum(plaintextCorrect)/len(plaintextCorrect))
