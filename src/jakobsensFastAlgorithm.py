from utils.utils import loadStatistics, selectPlainText
from encryption.monoalphabeticCipher import MonoalphabeticCipher
from collections import defaultdict
expectedDigramFrequencies = []

class DistributionMatrix:

    letterMatrix = [[] for _ in range(26)]
    rowMap = {}
    colMap = {}
    score = 0

    # TODO: Have frequencies put in (For the E matrix we need to precalc stats[first + second] * (ciphertextLength-1))
    # TODO: For spaced variants we need to change how expected distribution 
    def __init__(self, letterSequence, frequencies):

        for i, letter in enumerate(letterSequence):
            self.rowMap[letter] = i
            self.colMap[letter] = i


        for first in letterSequence:
            for second in letterSequence:
                rowIndex = self.rowMap[first]
                colIndex = self.colMap[second]
                self.letterMatrix[rowIndex][colIndex] = frequencies[first + second] * (ciphertextLength-1)
    
    def get(self, firstLetter, secondLetter):
        return self.letterMatrix[rowMap[firstLetter]][colMap[secondLetter]]
    
    def swapRowAndColumns(self, letterOne, letterTwo, expectationMatrix):
        rowOne = rowMap[letterOne]
        rowTwo = rowMap[letterTwo]
        expectationRowOne = expectationMatrix.rowMap[letterOne]
        expectationRowTwo = expectationMatrix.rowMap[letterTwo]
        self.rowMap[letterOne], self.rowMap[letterTwo] = self.rowMap[letterTwo], self.rowMap[letterOne]
        self.colMap[letterOne], self.colMap[letterTwo] = self.colMap[letterTwo], self.colMap[letterOne]

        previousScoreLoss = self.calculateScoreOnRowColumn(expectationMatrix, rowOne, rowTwo, expectationRowOne, expectationRowTwo)
        self.swapRows(rowOne, rowTwo)
        self.swapCols(rowOne, rowTwo)

        newScoreGain = self.calculateScoreOnRowColumn(expectationMatrix, rowOne, rowTwo, expectationRowTwo, expectationRowOne)
        self.score = self.score - previousScoreLoss + newScoreGain
        return previousScoreLoss

    def swapRows(self, rowOne, rowTwo):
        self.letterMatrix[rowOne], self.letterMatrix[rowTwo] = self.letterMatrix[rowTwo], self.letterMatrix[rowOne]

    def swapColumns(self, colOne, colTwo):
    
        for i in range(len(distributionMatrix)):
            if i != changedRowOne and i != changedRowTwo:
                self.letterMatrix[i][colOne], self.letterMatrix[i][colTwo] = self.letterMatrix[i][colTwo], self.letterMatrix[i][colOne]

    def calculateInitialScore(self, expectationMatrix):

        for letterOne, positionOne in self.rowMap.items():
                expectedPositionOne = expectationMatrix.rowMap[letterOne]
            for letterTwo, positionTwo in self.rowMap.items():
                expectationPositionTwo = expectationMatrix.rowMap[letterTwo]
                self.score += abs(self.letterMatrix[positionOne][positionTwo] - expectationMatrix.letterMatrix[expectationPositionOne][expectationPositionTwo])

    def calculateScoreOnRowColumn(self, expectationMatrix, changedRowOne, changedRowTwo, expectationRowOne, expectationRowTwo):

        score = 0
        for i in range(len(self.letterMatrix[changedRowOne])):
            score += abs(self.letterMatrix[changedRowOne][i] - expectationMatrix.letterMatrix[expectationRowOne][i])
            score += abs(self.letterMatrix[changedRowTwo][i] - expectationMatrix.letterMatrix[expectationRowTwo][i])
        
        for i in range(len(self.letterMatrix)):    
            if i != changedRowOne and i != changedRowTwo:
                score += abs(self.letterMatrix[i][changedRowOne] - expectationMatrix.letterMatrix[i][expectationRowOne])
                score += abs(self.letterMatrix[i][changedRowTwo] - expectationMatrix.letterMatrix[i][expectationRowTwo])

        return score

def swapElements(key, i, j):
    key[i], key[j] = key[j], key[i]

# Initialize the key maybe randomly, probably have most common unigram = most common ciphertext
def initializeExpectationMatrix(ciphertextLength):
    stats = loadStatistics(spacesRemoved=True)
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    expectedFrequencies = {}

    # Iterating through every digram possibility
    for first in alphabet:
        for second in alphabet:

            # Setting our expected number of occurances of each bigram, if the bigram is not expected at all (key error) we set to 0
            try:
                expectedFrequencies[first+second] = stats[first + second] * (ciphertextLength-1)
            except KeyError:
                expectedFrequencies[first+second] = 0

    # Creating a distribution matrix for our expected values
    return DistributionMatrix(alphabet, expectedFrequencies)

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
