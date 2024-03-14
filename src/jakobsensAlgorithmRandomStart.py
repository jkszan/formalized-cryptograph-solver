from jakobsensAlgorithm import jakobsensAlgorithm, initializeExpectationMatrix
from src.utils.utils import selectPlainText, loadStatistics
from src.encryption.monoalphabeticCipher import MonoalphabeticCipher
from src.utils.stats import calculateLanguageCertainty
import random

def generateInitialKey():
    key = {}
    LETTERORDER = "abcdefghijklmnopqrstuvwxyz"
    SELECTORDER = list(LETTERORDER)

    random.shuffle(SELECTORDER)

    for i in range(len(LETTERORDER)):
        key[LETTERORDER[i]] = SELECTORDER[i]

    return key

def testJakobsensRandomRestart(plaintext, numRestarts = 3, spacesRemoved = False):

    if spacesRemoved:
        plaintext = plaintext.replace(" ", "")

    # Creating cipher object and generating ciphertext
    cipher = MonoalphabeticCipher()
    ciphertext = cipher.encrypt(plaintext)

    # Generating the expected distribution matrix
    expectedDist = initializeExpectationMatrix(len(ciphertext), plaintextWords, spacesRemoved=spacesRemoved)

    statsJson = loadStatistics(spacesRemoved)

    minLanguageCert = float('inf')
    bestDerivedKey = None

    for i in range(numRestarts):

        initialKey = generateInitialKey()
        initialPunativePlaintext = cipher.decrypt(ciphertext, initialKey)

        derivedKey = jakobsensAlgorithm(ciphertext, initialKey, initialPunativePlaintext, expectedDist, spacesRemoved=spacesRemoved)
        proposedPlaintext = cipher.decrypt(ciphertext, derivedKey)

        languageCertaintyScore = calculateLanguageCertainty(proposedPlaintext, statsJson)

        if languageCertaintyScore < minLanguageCert:
            bestDerivedKey = derivedKey
            minLanguageCert = languageCertaintyScore

    print("\nFinal", cipher.evalProposedKey(ciphertext, bestDerivedKey))

    newLettersCorrect, newPlaintextCorrect = cipher.evalProposedKey(ciphertext, bestDerivedKey)

    return newLettersCorrect, newPlaintextCorrect


def testJakobsensRandomRestartCheating(plaintext, numRestarts = 3, spacesRemoved = False):

    if spacesRemoved:
        plaintext = plaintext.replace(" ", "")

    # Creating cipher object and generating ciphertext
    cipher = MonoalphabeticCipher()
    ciphertext = cipher.encrypt(plaintext)

    # Generating the expected distribution matrix
    expectedDist = initializeExpectationMatrix(len(ciphertext), plaintextWords, spacesRemoved=spacesRemoved)

    maxPlaintextCorrect = -1
    bestDerivedKey = None

    for i in range(numRestarts):

        initialKey = generateInitialKey()
        initialPunativePlaintext = cipher.decrypt(ciphertext, initialKey)

        derivedKey = jakobsensAlgorithm(ciphertext, initialKey, initialPunativePlaintext, expectedDist, spacesRemoved=spacesRemoved)

        _, plaintextCorrect = cipher.evalProposedKey(ciphertext, derivedKey)

        if maxPlaintextCorrect < plaintextCorrect:
            bestDerivedKey = derivedKey
            maxPlaintextCorrect = plaintextCorrect

    print("\nFinal", cipher.evalProposedKey(ciphertext, bestDerivedKey))

    newLettersCorrect, newPlaintextCorrect = cipher.evalProposedKey(ciphertext, bestDerivedKey)

    return newLettersCorrect, newPlaintextCorrect

if __name__ == "__main__":

    lettersCorrect = []
    plaintextCorrect = []
    plaintextWords = 50
    spacesRemoved = False
    numKeys = 3

    for i in range(100):

        # Generating and getting plaintext
        plaintext = selectPlainText(plaintextWords)
        #if spacesRemoved:
        #    plaintext = plaintext.replace(" ", "")

        #newLettersCorrect, newPlaintextCorrect = testJakobsensRandomRestartCheating(plaintext, spacesRemoved=spacesRemoved)
        newLettersCorrect, newPlaintextCorrect = testJakobsensRandomRestart(plaintext, spacesRemoved=spacesRemoved)
        lettersCorrect.append(newLettersCorrect)
        plaintextCorrect.append(newPlaintextCorrect)


    print("Average Letters Correct:", sum(lettersCorrect)/len(lettersCorrect))
    print("Average Plaintext Correct:", sum(plaintextCorrect)/len(plaintextCorrect))
