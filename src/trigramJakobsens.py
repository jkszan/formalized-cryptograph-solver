from jakobsensAlgorithmRandomStart import jakobsensRandomRestart as biJakobsensAlgorithm
from jakobsensAlgorithm import initializeExpectationMatrix as initBiExpectation
from utils.utils import loadStatistics, selectPlainText
from encryption.monoalphabeticCipher import MonoalphabeticCipher
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


class DistributionCube:

    # rowMap gives ciphertext to plaintext mappings

    def __init__(self, initialLetterKey, frequencies):
        """
            Constructor for DistributionCube, first initializes the rowMap to the initial key sequence then populates the letterMatrix
            with expected trigram frequencies
        """

        # Rowmap maps from index to Plaintext
        self.rowMap : dict[int, str] = {}

        # The bigram frequency matrix of the punative plaintext
        self.letterMatrix : list[list[int]] = [[[0]*len(LETTERORDER) for _ in range(len(LETTERORDER))] for _ in range(len(LETTERORDER))] # Square [0][0] corresponds to ciphertext bigram AA, and plaintext bigram rowMap[0] + colMap[0]

        for ciphertextLetter, plaintextLetter in initialLetterKey.items():
            self.rowMap[LETTERINDEX[ciphertextLetter]] = plaintextLetter

        self.rowMap[LETTERINDEX[" "]] = " "

        for firstIndex in range(len(LETTERORDER)):
            for secondIndex in range(len(LETTERORDER)):
                for thirdIndex in range(len(LETTERORDER)):
                    self.letterMatrix[firstIndex][secondIndex][thirdIndex] = frequencies[LETTERORDER[firstIndex] + LETTERORDER[secondIndex] + LETTERORDER[thirdIndex]]

    def swapRowAndColumns(self, rowOne, rowTwo):

        # Swap rows and columns
        self._swapRows(rowOne, rowTwo)
        self._swapColumns(rowOne, rowTwo)
        self._swapDepths(rowOne, rowTwo)
        self.rowMap[rowOne], self.rowMap[rowTwo] = self.rowMap[rowTwo], self.rowMap[rowOne]

    def _swapRows(self, rowOne, rowTwo):
        self.letterMatrix[rowOne], self.letterMatrix[rowTwo] = self.letterMatrix[rowTwo], self.letterMatrix[rowOne]

    def _swapColumns(self, colOne, colTwo):

        for i in range(len(self.letterMatrix)):
            self.letterMatrix[i][colOne], self.letterMatrix[i][colTwo] = self.letterMatrix[i][colTwo], self.letterMatrix[i][colOne]

    def _swapDepths(self, depthOne, depthTwo):
        for i in range(len(self.letterMatrix)):
            for j in range(len(self.letterMatrix)):
                self.letterMatrix[i][j][depthOne], self.letterMatrix[i][j][depthTwo] = self.letterMatrix[i][j][depthTwo], self.letterMatrix[i][j][depthOne]

    def calculateFullScore(self, expectationMatrix):

        score = 0
        for row in range(len(self.letterMatrix)):
            for col in range(len(self.letterMatrix[row])):
                for depth in range(len(self.letterMatrix[row][col])):
                    #score += pow(self.letterMatrix[row][col] - expectationMatrix.letterMatrix[row][col], 2)
                    score += abs(self.letterMatrix[row][col][depth] - expectationMatrix.letterMatrix[row][col][depth])
        return score

# Initialize the key maybe randomly, probably have most common unigram = most common ciphertext
def initializeExpectationMatrix(ciphertext, spacesRemoved=False):
    stats = loadStatistics(spacesRemoved=spacesRemoved)
    expectedFrequencies = {}
    letterKey = {}

    if not spacesRemoved:
        countSpaced = defaultdict(lambda: 0)

        for i in range(2, len(ciphertext)):
            first = ciphertext[i-2]
            second = ciphertext[i-1]
            third = ciphertext[i]

            if first == " " and third != " ":
                countSpaced[" 00"] += 1

            elif first == " " and third == " ":
                countSpaced[" 0 "] += 1

            elif second == " ":
                countSpaced["0 0"] += 1

            elif third == " " and first != " ":
                countSpaced["00 "] += 1

            else:
                countSpaced["000"] += 1


    # Iterating through every digram possibility
    for first in LETTERORDER:
        letterKey[first] = first
        for second in LETTERORDER:

            for third in LETTERORDER:
                # TODO: Need to actually count the number of in each space
                # Setting our expected number of occurances of each bigram, if the bigram is not expected at all (key error) we set to 0
                try:

                    if spacesRemoved:
                        expectedFrequencies[first+second+third] = stats[first+second+third]*(len(ciphertext))

                    elif first == " " and third != " ":
                        expectedFrequencies[first+second+third] = stats[first+second+third]*(countSpaced[" 00"])

                    elif first == " " and third == " ":
                        expectedFrequencies[first+second+third] = stats[first+second+third]*(countSpaced[" 0 "])

                    elif second == " ":
                        expectedFrequencies[first+second+third] = stats[first+second+third]*(countSpaced["0 0"])

                    elif third == " " and first != " ":
                        expectedFrequencies[first+second+third] = stats[first+second+third]*(countSpaced["00 "])

                    else:
                        expectedFrequencies[first+second+third] = stats[first+second+third]*(countSpaced["000"])


                except KeyError:
                    expectedFrequencies[first+second+third] = 0

    # Creating a distribution matrix for our expected values
    return DistributionCube(letterKey, expectedFrequencies)

def swapElements(key, i, j):
    key[i], key[j] = key[j], key[i]

def getTrigramFrequencies(punativePlaintext):
    trigramCounts = defaultdict(lambda: 0)

    for i in range(2, len(punativePlaintext)-1):
        trigramCounts[punativePlaintext[i-2:i+1]] += 1


    trigramFreq = defaultdict(lambda: 0)

    for trigram, count in trigramCounts.items():
        trigramFreq[trigram] = count


    return trigramFreq

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

def trigramJakobsensAlgorithm(punativeKey, punativePlaintext, expectedDist):

    trigramFrequencies = getTrigramFrequencies(punativePlaintext)

    trigramDist = DistributionCube(punativeKey, trigramFrequencies)

    a = 1
    b = 1
    done = False
    curScore = trigramDist.calculateFullScore(expectedDist)
    while not done:

        if a + b <= 26:
            trigramDist.swapRowAndColumns(a-1, a+b-1) # Step 7
            newScore = trigramDist.calculateFullScore(expectedDist)

            if newScore < curScore: # Step 9
                curScore = newScore
                swapElements(punativeKey, LETTERORDER[a-1], LETTERORDER[a+b-1])
                a = 1
                b = 1
            else:
                trigramDist.swapRowAndColumns(a-1, a+b-1)
                a = a + 1
                #assert digramDist.calculateFullScore(expectedDist) == curScore
        else:
            a = 1
            b = b + 1

            if b == 26:
                done = True
        print(curScore, end='\r')

    return punativeKey

def testJakobsensTrigramRestart(plaintext, plaintextWords, numRestarts = 3, spacesRemoved = False):
    if spacesRemoved:
        plaintext = plaintext.replace(" ", "")

    # Creating cipher object and generating ciphertext
    cipher = MonoalphabeticCipher()
    ciphertext = cipher.encrypt(plaintext)

    # Generating an initial key and decrypting the ciphertext into an initial plaintext guess
    biExpectedDist = initBiExpectation(len(ciphertext), plaintextWords, spacesRemoved)
    newInitialKey = biJakobsensAlgorithm(ciphertext, biExpectedDist, numRestarts=numRestarts, spacesRemoved=spacesRemoved)

    newPunativePlaintext = cipher.decrypt(ciphertext, newInitialKey)
    print("\nPre", cipher.evalProposedKey(ciphertext, newInitialKey))

    # Generating the expected distribution matrix
    expectedDist = initializeExpectationMatrix(ciphertext, spacesRemoved=spacesRemoved)

    # Running Jakobsens algorithm
    derivedKey = trigramJakobsensAlgorithm(newInitialKey, newPunativePlaintext, expectedDist)

    print("\nFinal", cipher.evalProposedKey(ciphertext, derivedKey))

    newLettersCorrect, newPlaintextCorrect = cipher.evalProposedKey(ciphertext, derivedKey)

    return newLettersCorrect, newPlaintextCorrect

def testJakobsensTrigramRepeatedIteration(plaintext, plaintextWords, numRestarts = 3, spacesRemoved = False):

    if spacesRemoved:
        plaintext = plaintext.replace(" ", "")

    # Creating cipher object and generating ciphertext
    cipher = MonoalphabeticCipher()
    ciphertext = cipher.encrypt(plaintext)

    # Generating an initial key and decrypting the ciphertext into an initial plaintext guess
    biExpectedDist = initBiExpectation(len(ciphertext), plaintextWords, spacesRemoved)
    newInitialKey = biJakobsensAlgorithm(ciphertext, biExpectedDist, numRestarts=numRestarts, spacesRemoved=spacesRemoved)
    biLettersCorrect, biPlaintextCorrect = cipher.evalProposedKey(ciphertext, newInitialKey)


    print("\nPre", cipher.evalProposedKey(ciphertext, newInitialKey))

    # Generating the expected distribution matrix
    expectedDist = initializeExpectationMatrix(ciphertext, spacesRemoved=spacesRemoved)

    # Running Jakobsens algorithm
    newPunativePlaintext = cipher.decrypt(ciphertext, newInitialKey)
    triKey = trigramJakobsensAlgorithm(newInitialKey, newPunativePlaintext, expectedDist)
    triLettersCorrect, triPlaintextCorrect = cipher.evalProposedKey(ciphertext, triKey)
    nextPunativePlaintext = cipher.decrypt(ciphertext, triKey)

    print("\nFinal", cipher.evalProposedKey(ciphertext, triKey))

    secondBiKey = biJakobsensAlgorithm(derivedKey, nextPunativePlaintext, biExpectedDist)
    secondBiPunativePlaintext = cipher.decrypt(ciphertext, secondBiKey)
    secondBiLettersCorrect, secondBiPlaintextCorrect = cipher.evalProposedKey(ciphertext, secondBiKey)


    secondTriKey = trigramJakobsensAlgorithm(secondBiKey, secondBiPunativePlaintext, expectedDist)


    secondTriLettersCorrect, secondTriPlaintextCorrect = cipher.evalProposedKey(ciphertext, secondTriKey)

    return (biLettersCorrect, biPlaintextCorrect), (triLettersCorrect, triPlaintextCorrect), (secondBiLettersCorrect, secondBiPlaintextCorrect), (secondTriLettersCorrect, secondTriPlaintextCorrect)




if __name__ == "__main__":
    lettersCorrect = []
    plaintextCorrect = []
    plaintextWords = 50
    spacesRemoved = True

    letterResults = {"Initial Bigram": [], "Initial Trigram": [], "Second Bigram": [], "Second Trigram": []}
    plaintextResults = {"Initial Bigram": [], "Initial Trigram": [], "Second Bigram": [], "Second Trigram": []}
    labels = ["Initial Bigram", "Initial Trigram", "Second Bigram", "Second Trigram"]


    for i in range(50):

        # Generating and getting plaintext
        plaintext = selectPlainText(plaintextWords)
        if spacesRemoved:
            plaintext = plaintext.replace(" ", "")


        #firstBi, firstTri, secondBi, secondTri = testJakobsensTrigramRepeatedIteration(plaintext, plaintextWords, numRestarts=5, spacesRemoved=spacesRemoved)
        results = list(testJakobsensTrigramRepeatedIteration(plaintext, plaintextWords, numRestarts=5, spacesRemoved=spacesRemoved))

        #results = [firstBi, firstTri, secondBi, secondTri]
        
        for i in range(len(labels)):
            letterResults[labels[i]].append(results[i][0])
            plaintextResults[labels[i]].append(results[i][1])

        # Average Letters Correct: 14.2
        # Average Plaintext Correct: 0.6389812739530298

    for label in labels:
        print("Average Letters Correct (" + label + "):", sum(letterResults[label])/len(letterResults[label]))
        print("Average Letters Correct (" + label + "):", sum(plaintextResults[label])/len(plaintextResults[label]))
        print("\n")


if False:
    lettersCorrect = []
    plaintextCorrect = []
    plaintextWords = 50
    spacesRemoved = True

    for i in range(50):

        # Generating and getting plaintext
        plaintext = selectPlainText(plaintextWords)
        if spacesRemoved:
            plaintext = plaintext.replace(" ", "")

        # Creating cipher object and generating ciphertext
        cipher = MonoalphabeticCipher()
        ciphertext = cipher.encrypt(plaintext)

        # Generating an initial key and decrypting the ciphertext into an initial plaintext guess
        biExpectedDist = initBiExpectation(len(ciphertext), plaintextWords, spacesRemoved)
        initialKey = generateInitialKey(ciphertext)
        initialPunativePlaintext = cipher.decrypt(ciphertext, initialKey)
        #newInitialKey = biJakobsensAlgorithm(initialKey, initialPunativePlaintext, biExpectedDist)
        newInitialKey = biJakobsensAlgorithm(ciphertext, biExpectedDist, numRestarts=5, spacesRemoved=spacesRemoved)
        newPunativePlaintext = cipher.decrypt(ciphertext, newInitialKey)
        print("\nPre", cipher.evalProposedKey(ciphertext, newInitialKey))

        # Generating the expected distribution matrix
        expectedDist = initializeExpectationMatrix(ciphertext, spacesRemoved=spacesRemoved)

        # Running Jakobsens algorithm
        derivedKey = trigramJakobsensAlgorithm(newInitialKey, newPunativePlaintext, expectedDist)

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
        # Average Letters Correct: 14.2
        # Average Plaintext Correct: 0.6389812739530298


    print("Average Letters Correct:", sum(lettersCorrect)/len(lettersCorrect))
    print("Average Plaintext Correct:", sum(plaintextCorrect)/len(plaintextCorrect))