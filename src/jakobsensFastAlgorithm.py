import sys,os
sys.path.append(os.getcwd())

from decimal import Decimal as D
from src.utils.utils import loadStatistics, selectPlainText
from src.encryption.monoalphabeticCipher import MonoalphabeticCipher
from collections import defaultdict

LETTERORDER = "abcdefghijklmnopqrstuvwxyz"
LETTERINDEX = {'a': 0, 'b': 1, 'c': 2, 'd': 3,
               'e': 4, 'f': 5, 'g': 6, 'h': 7,
               'i': 8, 'j': 9, 'k': 10, 'l': 11,
               'm': 12, 'n': 13, 'o': 14, 'p': 15,
               'q': 16, 'r': 17, 's': 18, 't': 19,
               'u': 20, 'v': 21, 'w': 22, 'x': 23,
               'y': 24, 'z': 25}
MOSTCOMMONORDER = "etaoinshrdlcumwfgypbvkjxqz"


class DistributionMatrix:


    # X | A  | B | C | D | E
    # A | AA | AB| AC| AD| AE
    # B | BA | BB| BC| BD| BE
    # Where 
    # rowMap gives ciphertext to plaintext mappings
    


    # TODO: Have frequencies put in (For the E matrix we need to precalc stats[first + second] * (ciphertextLength-1))
    # TODO: For spaced variants we need to change how expected distribution 
    def __init__(self, initialLetterKey, frequencies):
        """
            Constructor for DistributionMatrix, first initializes the rowMap to the initial key sequence then populates the letterMatrix
            with expected bigram frequencies
        """
        # The bigram frequency matrix of the punative plaintext
        self.letterMatrix : list[list[int]] = [[0]*26 for _ in range(26)] # Square [0][0] corresponds to ciphertext bigram AA, and plaintext bigram rowMap[0] + colMap[0]
        
        
        # Rowmap maps from index to Plaintext
        self.rowMap : dict[int, str] = {}

        for ciphertextLetter, plaintextLetter in initialLetterKey.items():
            self.rowMap[LETTERINDEX[ciphertextLetter]] = plaintextLetter

        for rowIndex in range(26):
            for colIndex in range(26):
                firstLetter = self.rowMap[rowIndex]
                secondLetter = self.rowMap[colIndex]

                self.letterMatrix[rowIndex][colIndex] = frequencies[firstLetter + secondLetter]
    
    def cipherTextToIndex(self, ciphertextLetter):
        return LETTERINDEX[ciphertextLetter]


    def get(self, firstIndex, secondIndex):
        """
        Helper function to get the bigram frequency of a plaintext bigram from two ciphertext indexes
        """
        return self.letterMatrix[firstIndex][secondIndex]
    
    def swapRowAndColumns(self, rowOne, rowTwo):

        # Swap rows and columns
        self.swapRows(rowOne, rowTwo)
        self.swapColumns(rowOne, rowTwo)
        self.rowMap[rowOne], self.rowMap[rowTwo] = self.rowMap[rowTwo], self.rowMap[rowOne]

    def swapRows(self, rowOne, rowTwo):
        self.letterMatrix[rowOne], self.letterMatrix[rowTwo] = self.letterMatrix[rowTwo], self.letterMatrix[rowOne]

    def swapColumns(self, colOne, colTwo):
    
        for i in range(len(self.letterMatrix)):
            self.letterMatrix[i][colOne], self.letterMatrix[i][colTwo] = self.letterMatrix[i][colTwo], self.letterMatrix[i][colOne]

    def calculateScoreOnRowColumn(self, expectationMatrix, rowOne, rowTwo):

        scoreDelta = 0
        for i in range(26):
            scoreDelta += abs(self.letterMatrix[rowOne][i] - expectationMatrix.letterMatrix[rowOne][i])
            scoreDelta += abs(self.letterMatrix[rowTwo][i] - expectationMatrix.letterMatrix[rowTwo][i])

        for i in range(26):    
            if i != rowOne and i != rowTwo:
                scoreDelta += abs(self.letterMatrix[i][rowOne] - expectationMatrix.letterMatrix[i][rowOne])
                scoreDelta += abs(self.letterMatrix[i][rowTwo] - expectationMatrix.letterMatrix[i][rowTwo])

        return round(scoreDelta, 15)
    
    def calculateFullScore(self, expectationMatrix):

        score = 0
        for row in range(len(self.letterMatrix)):
            for col in range(len(self.letterMatrix[row])):
                score += abs(self.letterMatrix[row][col] - expectationMatrix.letterMatrix[row][col])
        return score

def swapElements(key, i, j):
    key[i], key[j] = key[j], key[i]

# Initialize the key maybe randomly, probably have most common unigram = most common ciphertext
def initializeExpectationMatrix(ciphertextLength):
    stats = loadStatistics(spacesRemoved=True)
    expectedFrequencies = {}
    letterKey = {}

    # Iterating through every digram possibility
    for first in LETTERORDER:
        letterKey[first] = first
        for second in LETTERORDER:

            # Setting our expected number of occurances of each bigram, if the bigram is not expected at all (key error) we set to 0
            try:
                expectedFrequencies[first+second] = D(stats[first + second] * (ciphertextLength-1))
            except KeyError:
                expectedFrequencies[first+second] = 0

    # Creating a distribution matrix for our expected values
    return DistributionMatrix(letterKey, expectedFrequencies)

def getDigramFreq(punativePlaintext):
    digramCounts = defaultdict(lambda: 0)

    for i in range(len(punativePlaintext)-1):
        digramCounts[punativePlaintext[i-1:i+1]] += 1
    
    digramTotal = len(punativePlaintext) - 1
    digramFreq = defaultdict(lambda: 0)
    for digram, count in digramCounts.items():
        digramFreq[digram] = D(count/digramTotal)
    
    return digramFreq

def generateInitialKey(ciphertext):

    letterCounts = {}

    for letter in LETTERORDER:
        letterCounts[letter] = 0

    for letter in ciphertext:
        letterCounts[letter] += 1
    
    letterOrder = list(letterCounts.items())
    letterOrder.sort(key=lambda x: -x[1])

    initialKey = {}

    for i in range(len(letterOrder)):
        nextLetter = letterOrder[i][0]
        initialKey[nextLetter] = MOSTCOMMONORDER[i]

    return initialKey

# TODO: Fix so key is dictionary
def jakobsensFastAlgorithm():

    plaintext = selectPlainText(1000)
    plaintext = plaintext.replace(" ", "")
    cipher = MonoalphabeticCipher()
    ciphertext = cipher.encrypt(plaintext)

    punativeKey = generateInitialKey(ciphertext)
    #print(punativeKey)
    punativePlaintext = cipher.decrypt(ciphertext, punativeKey)
    
    digramFrequencies = getDigramFreq(punativePlaintext)
    digramDist = DistributionMatrix(punativeKey, digramFrequencies)
    expectedDist = initializeExpectationMatrix(len(ciphertext))
    #print(digramDist.rowMap)
    #print(expectedDist, digramDist)
    #print(expectedDist.letterMatrix == digramDist.letterMatrix)
    #print(expectedDist.rowMap == digramDist.rowMap)

    #lastIterScore = float('inf')
    #while lastIterScore > digramDist.score:
    #    lastIterScore = digramDist.score
    a = 1
    b = 1
    done = False
    while not done:
        #print(a, b)
        #curScore = digramDist.calculateFullScore(expectedDist)

        if a + b <= 26:
            curValue = digramDist.calculateScoreOnRowColumn(expectedDist, a-1, a+b-1)
            digramDist.swapRowAndColumns(a-1, a+b-1) # Step 7
            newValue = digramDist.calculateScoreOnRowColumn(expectedDist, a-1, a+b-1) # Step 8
            #print(curValue, newValue)
            #print(newValue - curValue)
            if newValue < curValue: # Step 9
                swapElements(punativeKey, digramDist.rowMap[a-1], digramDist.rowMap[a+b-1])
                a = 1
                b = 1
            else:
                digramDist.swapRowAndColumns(a-1, a+b-1)
                a = a + 1
        else:
            a = 1
            b = b + 1

            if b == 26:
                done = True


    punativePlaintext = cipher.decrypt(ciphertext, punativeKey)
    #print(plaintext, "\n")
    print(cipher.evalProposedKey(ciphertext, punativeKey))
    #print(ciphertext)
    #print(plaintext)
    #print(punativePlaintext)
    return punativeKey, punativePlaintext


for i in range(10):
    punativeKey, punativePlaintext = jakobsensFastAlgorithm()
    #print(punativePlaintext, "\n", punativeKey)

