from src.jakobsensAlgorithm import jakobsensAlgorithm, initializeExpectationMatrix
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

def jakobsensRandomRestart(ciphertext, expectedDist, numRestarts = 3, spacesRemoved = False):
    statsJson = loadStatistics(spacesRemoved)

    minLanguageCert = float('inf')
    bestDerivedKey = None

    # Creating cipher object and generating ciphertext
    cipher = MonoalphabeticCipher()

    for _ in range(numRestarts):

        initialKey = generateInitialKey()
        initialPunativePlaintext = cipher.decrypt(ciphertext, initialKey)

        derivedKey = jakobsensAlgorithm(initialKey, initialPunativePlaintext, expectedDist)
        proposedPlaintext = cipher.decrypt(ciphertext, derivedKey)

        #print("Fair oracle val:", cipher.evalProposedKey(ciphertext, derivedKey), calculateLanguageCertainty(proposedPlaintext, statsJson))

        languageCertaintyScore = calculateLanguageCertainty(proposedPlaintext, statsJson)

        if languageCertaintyScore < minLanguageCert:
            bestDerivedKey = derivedKey
            minLanguageCert = languageCertaintyScore
    
    return bestDerivedKey


def testJakobsensRandomRestart(plaintext, plaintextWords, numRestarts = 3, spacesRemoved = False):

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

    for _ in range(numRestarts):

        initialKey = generateInitialKey()
        initialPunativePlaintext = cipher.decrypt(ciphertext, initialKey)

        derivedKey = jakobsensAlgorithm(initialKey, initialPunativePlaintext, expectedDist)
        proposedPlaintext = cipher.decrypt(ciphertext, derivedKey)

        #print("Fair oracle val:", cipher.evalProposedKey(ciphertext, derivedKey), calculateLanguageCertainty(proposedPlaintext, statsJson))

        languageCertaintyScore = calculateLanguageCertainty(proposedPlaintext, statsJson)

        if languageCertaintyScore < minLanguageCert:
            bestDerivedKey = derivedKey
            minLanguageCert = languageCertaintyScore

    #print("\nFinal", cipher.evalProposedKey(ciphertext, bestDerivedKey))

    newLettersCorrect, newPlaintextCorrect = cipher.evalProposedKey(ciphertext, bestDerivedKey)

    return newLettersCorrect, newPlaintextCorrect


def testJakobsensRandomRestartCheating(plaintext, plaintextWords, numRestarts = 3, spacesRemoved = False):

    if spacesRemoved:
        plaintext = plaintext.replace(" ", "")

    # Creating cipher object and generating ciphertext
    cipher = MonoalphabeticCipher()
    ciphertext = cipher.encrypt(plaintext)

    # Generating the expected distribution matrix
    expectedDist = initializeExpectationMatrix(len(ciphertext), plaintextWords, spacesRemoved=spacesRemoved)

    maxPlaintextCorrect = -1
    bestDerivedKey = None

    for _ in range(numRestarts):

        initialKey = generateInitialKey()
        initialPunativePlaintext = cipher.decrypt(ciphertext, initialKey)

        derivedKey = jakobsensAlgorithm(initialKey, initialPunativePlaintext, expectedDist)

        _, plaintextCorrect = cipher.evalProposedKey(ciphertext, derivedKey)

        if maxPlaintextCorrect < plaintextCorrect:
            bestDerivedKey = derivedKey
            maxPlaintextCorrect = plaintextCorrect

    #print("\nFinal (Cheat)", cipher.evalProposedKey(ciphertext, bestDerivedKey))

    newLettersCorrect, newPlaintextCorrect = cipher.evalProposedKey(ciphertext, bestDerivedKey)

    return newLettersCorrect, newPlaintextCorrect

if __name__ == "__main__":

    lettersCorrect = []
    plaintextCorrect = []
    fairLet = []
    fairPlain = []
    plaintextWords = 50
    spacesRemoved = False
    numKeys = 3

    for i in range(5):

        # Generating and getting plaintext
        plaintext = selectPlainText(plaintextWords)
        #if spacesRemoved:
        #    plaintext = plaintext.replace(" ", "")

        newLettersCorrect, newPlaintextCorrect = testJakobsensRandomRestartCheating(plaintext, plaintextWords, numKeys, spacesRemoved=spacesRemoved)
        fairNewLettersCorrect, fairNewPlaintextCorrect = testJakobsensRandomRestart(plaintext, plaintextWords, numKeys, spacesRemoved=spacesRemoved)
        fairLet.append(fairNewLettersCorrect)
        fairPlain.append(fairNewPlaintextCorrect)
        lettersCorrect.append(newLettersCorrect)
        plaintextCorrect.append(newPlaintextCorrect)


    print("Average Letters Correct:", sum(lettersCorrect)/len(lettersCorrect))
    print("Average Plaintext Correct:", sum(plaintextCorrect)/len(plaintextCorrect))

    print("Average Fair Letters Correct:", sum(fairLet)/len(lettersCorrect))
    print("Average Fair Plaintext Correct:", sum(fairPlain)/len(plaintextCorrect))
