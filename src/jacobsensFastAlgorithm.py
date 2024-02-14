from utils.utils import loadStatistics, selectPlainText
from encryption.monoalphabeticCipher import MonoalphabeticCipher
expectedDigramFrequencies = []

class ExpectationMatrix:

    expectationMatrix = [[] for _ in range(26)]
    rowMap = {}
    colMap = {}

    def __init__(self, ciphertextLength):

        alphabet = "abcdefghijklmnopqrstuvwxyz"
        stats = loadStatistics(spacesRemoved=True)

        for i, letter in enumerate(alphabet):
            self.rowMap[letter] = i
            self.colMap[letter] = i


        for first in alphabet:
            for second in alphabet:
                rowIndex = self.rowMap[first]
                colIndex = self.colMap[second]
                self.expectationMatrix[rowIndex][colIndex] = stats[first + second] * (ciphertextLength-1)


    def getExpected(self, first, second):
        rowIndex = self.rowMap[first]
        colIndex = self.colMap[second]
        return self.expectationMatrix[rowIndex][colIndex]
    
def swapRows(rowOne, rowTwo):
    pass

def swapCols(colOne, colTwo):
    pass

def calculateScore(self, punativeKey):
    pass

def swapElements(key, i, j):
    key[i], key[j] = key[j], key[i]



# TODO: Consider class just for this
def getExpectationMatrix(ciphertextLength):
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    stats = loadStatistics(spacesRemoved=False)
    expectationMatrix = [[] for _ in range(26)]
    rowMap = {}
    colMap = {}

    for i, letter in enumerate(alphabet):
        rowMap[letter] = i
        colMap[letter] = i


    for first in alphabet:
        for second in alphabet:
            rowIndex = rowMap[first]
            colIndex = colMap[second]
            expectationMatrix[rowIndex][colIndex] = stats[first + second]

    return expectationMatrix, rowMap, colMap

def generateInitialKey(ciphertext):
    pass

def getDigramFreq(text):
    pass

def jakobsensFastAlgorithm():

    plaintext = selectPlainText(50)
    plaintext = plaintext.replace(" ", "")
    cipher = MonoalphabeticCipher()
    ciphertext = cipher.encrypt(plaintext)

    punativeKey = generateInitialKey(ciphertext)
    punativePlaintext = cipher.decrypt(ciphertext, punativeKey)

    digramDist = getDigramFreq(punativePlaintext)
    expectedDist = ExpectationMatrix(len(ciphertext))
    currentScore = calculateScore(digramDist, expectedDist)

    for i in range(26):
        for j in range(26-i):
            
            # TODO: Have digramDist turn into the proposed, turning back after failing score
            digramDistProposed = digramDist.deepcopy() # Problem here, we can't have this shit. Need to have it such that D is transformed into D' efficiently
            swapRows(digramDistProposed, j, j+i)
            swapCols(digramDistProposed, j, j+i)

            # TODO: Have calculateScore take into account currentScore + the two values that have changed. So we don't need to recompute every time
            punativeScore = calculateScore(digramDistProposed, expectedDist, currentScore, i, j)
            if punativeScore < currentScore:
                digramDist = digramDistProposed
                swapElements(punativeKey, j, j+i)
                currentScore = punativeScore
            else:
                # TODO: Convert D' back to D
                swapRows(digramDistProposed, j, j+i)
                swapCols(digramDistProposed, j, j+i)

    punativePlaintext = cipher.decrypt(ciphertext, punativeKey)
    return punativeKey, punativePlaintext
