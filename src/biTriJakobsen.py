from encryption.monoalphabeticCipher import MonoalphabeticCipher
from utils.utils import selectPlainText

from jakobsensAlgorithm import initializeExpectationMatrix as initializeBigramExpectation, getDigramFrequencies, DistributionMatrix, generateInitialKey
from trigramJakobsens import initializeExpectationMatrix as initializeTrigramExpectation, getTrigramFrequencies, DistributionCube

LETTERORDER = "abcdefghijklmnopqrstuvwxyz "
LETTERINDEX = {'a': 0, 'b': 1, 'c': 2, 'd': 3,
               'e': 4, 'f': 5, 'g': 6, 'h': 7,
               'i': 8, 'j': 9, 'k': 10, 'l': 11,
               'm': 12, 'n': 13, 'o': 14, 'p': 15,
               'q': 16, 'r': 17, 's': 18, 't': 19,
               'u': 20, 'v': 21, 'w': 22, 'x': 23,
               'y': 24, 'z': 25, ' ': 26}
MOSTCOMMONORDER = "etaoinshrdlcumwfgypbvkjxqz"


class DistributionMeasure:

    def __init__(self, initialLetterKey, digramFrequencies, trigramFrequencies, expectedDigramDist, expectedTrigramDist):

        # Rowmap maps from index to Plaintext
        self.rowMap : dict[int, str] = {}

        for ciphertextLetter, plaintextLetter in initialLetterKey.items():
            self.rowMap[LETTERINDEX[ciphertextLetter]] = plaintextLetter

        self.rowMap[LETTERINDEX[" "]] = " "

        self.distributionCube = DistributionCube(initialLetterKey, trigramFrequencies)
        self.distributionMatrix = DistributionMatrix(initialLetterKey, digramFrequencies)

        self.digramExpectation = expectedDigramDist
        self.trigramExpectation = expectedTrigramDist

        self.initialCubeScore = self.distributionCube.calculateFullScore(expectedTrigramDist)
        self.initialMatrixScore = self.distributionMatrix.calculateFullScore(expectedDigramDist)

    def swapRowAndColumns(self, rowOne, rowTwo):
        self.distributionCube.swapRowAndColumns(rowOne, rowTwo)
        self.distributionMatrix.swapRowAndColumns(rowOne, rowTwo)
        self.rowMap[rowOne], self.rowMap[rowTwo] = self.rowMap[rowTwo], self.rowMap[rowOne]

    def calculateFullScore(self):

        cubeComponent = self.distributionCube.calculateFullScore(self.trigramExpectation)# / self.initialCubeScore
        matrixComponent = self.distributionMatrix.calculateFullScore(self.digramExpectation)# / self.initialMatrixScore
        return 0.5*cubeComponent + matrixComponent



def swapElements(key, i, j):
    key[i], key[j] = key[j], key[i]

def biTriJakobsensAlgorithm(punativeKey, punativePlaintext, expectedDigramDist, expectedTrigramDist):

    digramFrequencies = getDigramFrequencies(punativePlaintext)
    trigramFrequencies = getTrigramFrequencies(punativePlaintext)

    distributionMeasure = DistributionMeasure(punativeKey, digramFrequencies, trigramFrequencies, expectedDigramDist, expectedTrigramDist)

    a = 1
    b = 1
    done = False
    curScore = distributionMeasure.calculateFullScore()
    while not done:

        if a + b <= 26:
            distributionMeasure.swapRowAndColumns(a-1, a+b-1) # Step 7
            newScore = distributionMeasure.calculateFullScore()

            if newScore < curScore: # Step 9
                curScore = newScore
                swapElements(punativeKey, LETTERORDER[a-1], LETTERORDER[a+b-1])
                a = 1
                b = 1
            else:
                distributionMeasure.swapRowAndColumns(a-1, a+b-1)
                a = a + 1
        else:
            a = 1
            b = b + 1

            if b == 26:
                done = True
        print(curScore, end='\r')

    return punativeKey

def testBiTriJakobsens(plaintext, plaintextWords, spacesRemoved = False):
    if spacesRemoved:
        plaintext = plaintext.replace(" ", "")

    # Creating cipher object and generating ciphertext
    cipher = MonoalphabeticCipher()
    ciphertext = cipher.encrypt(plaintext)

    # Generating an initial key and decrypting the ciphertext into an initial plaintext guess
    bigramExpectedDist = initializeBigramExpectation(len(ciphertext), plaintextWords, spacesRemoved)
    trigramExpectedDist = initializeTrigramExpectation(ciphertext, spacesRemoved)
    initialKey = generateInitialKey(ciphertext)
    punativePlaintext = cipher.decrypt(ciphertext, initialKey)

    # Running Jakobsens algorithm
    derivedKey = biTriJakobsensAlgorithm(initialKey, punativePlaintext, bigramExpectedDist, trigramExpectedDist)

    print("\nFinal", cipher.evalProposedKey(ciphertext, derivedKey))

    newLettersCorrect, newPlaintextCorrect = cipher.evalProposedKey(ciphertext, derivedKey)

    return newLettersCorrect, newPlaintextCorrect

if __name__ == "__main__":
    lettersCorrect = []
    plaintextCorrect = []
    plaintextWords = 50
    spacesRemoved = True

    for i in range(50):

        # Generating and getting plaintext
        plaintext = selectPlainText(plaintextWords)

        newLettersCorrect, newPlaintextCorrect = testBiTriJakobsens(plaintext, plaintextWords, spacesRemoved)

        lettersCorrect.append(newLettersCorrect)
        plaintextCorrect.append(newPlaintextCorrect)
        # Average Letters Correct: 14.2
        # Average Plaintext Correct: 0.6389812739530298


    print("Average Letters Correct:", sum(lettersCorrect)/len(lettersCorrect))
    print("Average Plaintext Correct:", sum(plaintextCorrect)/len(plaintextCorrect))