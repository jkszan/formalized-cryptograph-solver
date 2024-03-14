import sys,os
sys.path.append(os.getcwd())

from src.utils.utils import loadStatistics, selectPlainText
from src.encryption.monoalphabeticCipher import MonoalphabeticCipher
from collections import defaultdict

LETTERORDER = "abcdefghijklmnopqrstuvwxyz "
LETTERINDEX = {'a': 0, 'b': 1, 'c': 2, 'd': 3,
               'e': 4, 'f': 5, 'g': 6, 'h': 7,
               'i': 8, 'j': 9, 'k': 10, 'l': 11,
               'm': 12, 'n': 13, 'o': 14, 'p': 15,
               'q': 16, 'r': 17, 's': 18, 't': 19,
               'u': 20, 'v': 21, 'w': 22, 'x': 23,
               'y': 24, 'z': 25, ' ': 26}
MOSTCOMMONORDER = "etaoinshrdlcumwfgypbvkjxqz"


class DistributionMatrix:

    # rowMap gives ciphertext to plaintext mappings

    def __init__(self, initialLetterKey, frequencies):
        """
            Constructor for DistributionMatrix, first initializes the rowMap to the initial key sequence then populates the letterMatrix
            with expected bigram frequencies
        """

        # Rowmap maps from index to Plaintext
        self.rowMap : dict[int, str] = {}

        # The bigram frequency matrix of the punative plaintext
        self.letterMatrix : list[list[int]] = [[0]*len(LETTERORDER) for _ in range(len(LETTERORDER))] # Square [0][0] corresponds to ciphertext bigram AA, and plaintext bigram rowMap[0] + colMap[0]

        for ciphertextLetter, plaintextLetter in initialLetterKey.items():
            self.rowMap[LETTERINDEX[ciphertextLetter]] = plaintextLetter

        self.rowMap[LETTERINDEX[" "]] = " "

        for rowIndex in range(len(LETTERORDER)):
            for colIndex in range(len(LETTERORDER)):
                self.letterMatrix[rowIndex][colIndex] = frequencies[LETTERORDER[rowIndex] + LETTERORDER[colIndex]]

    def swapRowAndColumns(self, rowOne, rowTwo):

        # Swap rows and columns
        self._swapRows(rowOne, rowTwo)
        self._swapColumns(rowOne, rowTwo)
        self.rowMap[rowOne], self.rowMap[rowTwo] = self.rowMap[rowTwo], self.rowMap[rowOne]

    def _swapRows(self, rowOne, rowTwo):
        self.letterMatrix[rowOne], self.letterMatrix[rowTwo] = self.letterMatrix[rowTwo], self.letterMatrix[rowOne]

    def _swapColumns(self, colOne, colTwo):

        for i in range(len(self.letterMatrix)):
            self.letterMatrix[i][colOne], self.letterMatrix[i][colTwo] = self.letterMatrix[i][colTwo], self.letterMatrix[i][colOne]

    def calculateFullScore(self, expectationMatrix):

        score = 0
        for row in range(len(self.letterMatrix)):
            for col in range(len(self.letterMatrix[row])):
                #score += pow(self.letterMatrix[row][col] - expectationMatrix.letterMatrix[row][col], 2)
                score += abs(self.letterMatrix[row][col] - expectationMatrix.letterMatrix[row][col])
        return score

# Initialize the key maybe randomly, probably have most common unigram = most common ciphertext
def initializeExpectationMatrix(ciphertextLength, wordCount, spacesRemoved=False):
    stats = loadStatistics(spacesRemoved=spacesRemoved)
    expectedFrequencies = {}
    letterKey = {}

    # Iterating through every digram possibility
    for first in LETTERORDER:
        letterKey[first] = first
        for second in LETTERORDER:

            # Setting our expected number of occurances of each bigram, if the bigram is not expected at all (key error) we set to 0
            try:

                if spacesRemoved:
                    expectedFrequencies[first+second] = stats[first+second]*(ciphertextLength - 1)

                elif first == " ":
                    expectedFrequencies[first+second] = stats[first+second]*(wordCount-1)

                elif second == " ":
                    expectedFrequencies[first+second] = stats[first+second]*(wordCount-1)

                else:
                    expectedFrequencies[first+second] = stats[first+second]*(ciphertextLength - (2*(wordCount-1) + 1))


            except KeyError:
                expectedFrequencies[first+second] = 0

    # Creating a distribution matrix for our expected values
    return DistributionMatrix(letterKey, expectedFrequencies)

def swapElements(key, i, j):
    key[i], key[j] = key[j], key[i]

def getDigramFrequencies(punativePlaintext):
    digramCounts = defaultdict(lambda: 0)

    for i in range(1, len(punativePlaintext)-1):
        digramCounts[punativePlaintext[i-1:i+1]] += 1


    digramFreq = defaultdict(lambda: 0)

    for digram, count in digramCounts.items():
        digramFreq[digram] = count


    return digramFreq

def generateInitialKey(ciphertext):

    letterCounts = {}

    for letter in LETTERORDER:

        if letter != " ":
            letterCounts[letter] = 0

    for letter in ciphertext:
        if letter != " ":
            letterCounts[letter] += 1

    letterOrder = list(letterCounts.items())
    letterOrder.sort(key=lambda x: -x[1])

    initialKey = {}

    for i in range(len(letterOrder)):
        nextLetter = letterOrder[i][0]
        initialKey[nextLetter] = MOSTCOMMONORDER[i]

    return initialKey

def jakobsensAlgorithm(punativeKey, punativePlaintext, expectedDist):


    digramFrequencies = getDigramFrequencies(punativePlaintext)

    digramDist = DistributionMatrix(punativeKey, digramFrequencies)

    a = 1
    b = 1
    done = False
    curScore = digramDist.calculateFullScore(expectedDist)
    while not done:

        if a + b <= 26:
            digramDist.swapRowAndColumns(a-1, a+b-1) # Step 7
            newScore = digramDist.calculateFullScore(expectedDist)

            if newScore < curScore: # Step 9
                curScore = newScore
                swapElements(punativeKey, LETTERORDER[a-1], LETTERORDER[a+b-1])
                a = 1
                b = 1
            else:
                digramDist.swapRowAndColumns(a-1, a+b-1)
                a = a + 1
                #assert digramDist.calculateFullScore(expectedDist) == curScore
        else:
            a = 1
            b = b + 1

            if b == 26:
                done = True
        print(curScore, end='\r')

    return punativeKey

def testJakobsens(plaintext, plaintextWords, spacesRemoved = False):

    if spacesRemoved:
        plaintext = plaintext.replace(" ", "")

    # Creating cipher object and generating ciphertext
    cipher = MonoalphabeticCipher()
    ciphertext = cipher.encrypt(plaintext)

    # Generating an initial key and decrypting the ciphertext into an initial plaintext guess
    initialKey = generateInitialKey(ciphertext)
    initialPunativePlaintext = cipher.decrypt(ciphertext, initialKey)

    # Generating the expected distribution matrix
    expectedDist = initializeExpectationMatrix(len(ciphertext), plaintextWords, spacesRemoved=spacesRemoved)

    # Running Jakobsens algorithm
    derivedKey = jakobsensAlgorithm(initialKey, initialPunativePlaintext, expectedDist)

    print("\nFinal", cipher.evalProposedKey(ciphertext, derivedKey))

    newLettersCorrect, newPlaintextCorrect = cipher.evalProposedKey(ciphertext, derivedKey)

    return newLettersCorrect, newPlaintextCorrect

if __name__ == "__main__":
    lettersCorrect = []
    plaintextCorrect = []
    plaintextWords = 500
    spacesRemoved = False

    for i in range(1):

        # Generating and getting plaintext
        plaintext = selectPlainText(plaintextWords)
        if spacesRemoved:
            plaintext = plaintext.replace(" ", "")

        # Creating cipher object and generating ciphertext
        cipher = MonoalphabeticCipher()
        ciphertext = cipher.encrypt(plaintext)

        # Generating an initial key and decrypting the ciphertext into an initial plaintext guess
        initialKey = generateInitialKey(ciphertext)
        initialPunativePlaintext = cipher.decrypt(ciphertext, initialKey)

        # Generating the expected distribution matrix
        expectedDist = initializeExpectationMatrix(len(ciphertext), plaintextWords, spacesRemoved=spacesRemoved)

        # Running Jakobsens algorithm
        derivedKey = jakobsensAlgorithm(initialKey, initialPunativePlaintext, expectedDist)

        print("\nFinal", cipher.evalProposedKey(ciphertext, derivedKey))

        print("Correct Keys:")
        realKey = cipher.keyCodex
        for key, val in derivedKey.items():
            if realKey[key] == val:
                print(val, end = " ")
        print("")

        newLettersCorrect, newPlaintextCorrect = cipher.evalProposedKey(ciphertext, derivedKey)
        lettersCorrect.append(newLettersCorrect)
        plaintextCorrect.append(newPlaintextCorrect)


    print("Average Letters Correct:", sum(lettersCorrect)/len(lettersCorrect))
    print("Average Plaintext Correct:", sum(plaintextCorrect)/len(plaintextCorrect))
